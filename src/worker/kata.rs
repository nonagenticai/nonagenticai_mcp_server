//! The Kata sandbox backend: pod CRUD and the attach websocket.
//!
//! This is a faithful port of the reference's `src/execution/kata.py` (commit `22ac1ce4`):
//! the pod manifest (`kata.py:15-83`), the record parser (`kata.py:86-99`) and the six backend
//! operations (`kata.py:162-302`). Kubernetes is an external boundary, so no other module talks
//! to the API server.
//!
//! In-cluster only, exactly like the reference: there is no exec, no secret read and no local
//! fallback. The API client comes from the pod's service account, and the executor's RBAC is
//! scoped to pods in `MCP_RUN_NAMESPACE` plus one `RuntimeClass` read.
//!
//! The attach websocket handshake itself is not exercised by the test suite: `tests/worker_kata.rs`
//! drives [`KataAttach`]'s buffered-read rules over `tokio::io::simplex`, and the websocket leg is
//! proven at the in-cluster cutover (a real pod, a real attach, the runner protocol's first
//! `ready` frame). Everything below the websocket — the identity fence, the deterministic name,
//! the UID-preconditioned delete and the confirm-by-inspection loop — is tested against a local
//! mock of the Kubernetes core API.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod as KubePod;
use kube::api::{
    Api, ApiResource, AttachParams, AttachedProcess, DeleteParams, DynamicObject, GroupVersionKind,
    ListParams, PostParams, Preconditions,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf};

use crate::catalog::models::{ToolLimits, ToolManifest};
use crate::config::WorkerSettings;
use crate::worker::backend::{
    AttachChannel, Backend, BackendError, Pod, STOP_CONFIRM_ATTEMPTS, STOP_CONFIRM_INTERVAL,
    pod_name,
};
use crate::worker::row::WorkerRow;

/// The label selector that defines "this executor's inventory" (`kata.py:292`).
const MANAGED_BY: &str = "app.kubernetes.io/managed-by=mcp-executor";
/// The pod's one container: the sandboxed runner (`kata.py:54`).
const RUNNER_CONTAINER: &str = "runner";

/// The Kubernetes (Kata) sandbox backend.
///
/// One instance per worker process. `pods` is bound to `MCP_RUN_NAMESPACE`; every pod it
/// creates, adopts, attaches to or deletes is in that namespace.
pub struct Kata {
    /// Kept separate from `pods` for the dynamic `RuntimeClass` read [`Kata::ready`] performs.
    client: kube::Client,
    /// The executor settings, including the namespace and the image/runtime-class allowlist.
    settings: WorkerSettings,
    /// The typed pod API bound to the run namespace.
    pods: Api<KubePod>,
}

impl Kata {
    /// Bind the backend to `run_namespace`.
    ///
    /// The namespace is refused when empty: `Api::namespaced` would build
    /// `/api/v1/namespaces//pods`, so an unset namespace must fail here rather than become a
    /// malformed request per call. `WorkerSettings::validate` separately pins it to `mcp-runs`.
    pub fn new(client: kube::Client, settings: WorkerSettings) -> Result<Self, BackendError> {
        if settings.run_namespace.trim().is_empty() {
            return Err(BackendError::Denied("the run namespace is unset"));
        }
        let pods = Api::namespaced(client.clone(), &settings.run_namespace);
        Ok(Self {
            client,
            settings,
            pods,
        })
    }

    /// The runner pod manifest for one run, exactly as `kata.pod_manifest` builds it.
    ///
    /// The runner image comes from the run's **snapshotted** manifest (`authority.manifest`),
    /// never from the request or the live catalog, and it must equal the operator's configured
    /// digest and appear in the approved list. A run whose snapshot disagrees is refused before
    /// anything reaches the API server.
    ///
    /// The limits are capped by the operator's settings, not by the tool: a tool may ask for
    /// more than the operator allows but never receive it.
    pub fn pod_manifest(
        row: &WorkerRow,
        settings: &WorkerSettings,
        limits: &ToolLimits,
    ) -> Result<Value, BackendError> {
        let manifest = snapshot_manifest(row)?;
        let configured = settings
            .runner_image_digest
            .as_deref()
            .filter(|value| !value.is_empty());
        let runtime_class = settings
            .kata_runtime_class
            .as_deref()
            .filter(|value| !value.is_empty());
        let image = manifest
            .runner_image_digest
            .as_ref()
            .map(|digest| digest.as_str());
        let (Some(runtime_class), Some(configured), Some(image)) =
            (runtime_class, configured, image)
        else {
            return Err(BackendError::Denied(
                "the run needs a Kata runtime class and a runner image digest",
            ));
        };
        if image != configured
            || !settings
                .approved_runner_images
                .iter()
                .map(String::as_str)
                .any(|approved| approved == image)
        {
            return Err(BackendError::Denied(
                "the run's runner image is not the approved digest",
            ));
        }

        let memory = limits.memory_mi.min(settings.run_memory_limit_mi);
        let cpu = limits.cpu_millicores.min(settings.run_cpu_limit);
        let request_memory = memory.min(settings.run_memory_request_mi);
        let request_cpu = cpu.min(settings.run_cpu_request);
        // `run_start_timeout + ceil(min(wall_seconds, run_max))`; every term is a whole number of
        // seconds, so the ceiling is the integer itself.
        let wall_seconds = u64::from(limits.wall_seconds).min(settings.run_max.as_secs());
        let deadline = settings.run_start_timeout.as_secs() + wall_seconds;

        Ok(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name(&row.run.run_id, row.fence),
                "namespace": settings.run_namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "mcp-executor",
                    "mcp.run-id": row.run.run_id.to_string(),
                    "mcp.fence": row.fence.to_string(),
                },
            },
            "spec": {
                "runtimeClassName": runtime_class,
                "restartPolicy": "Never",
                "automountServiceAccountToken": false,
                "enableServiceLinks": false,
                "terminationGracePeriodSeconds": 1,
                "activeDeadlineSeconds": deadline,
                "securityContext": {
                    "runAsNonRoot": true,
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": RUNNER_CONTAINER,
                    "image": image,
                    // The digest is mandatory and immutable; permit air-gapped clusters to
                    // provision the reviewed digest into containerd.
                    "imagePullPolicy": "IfNotPresent",
                    "stdin": true,
                    "stdinOnce": true,
                    "tty": false,
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "resources": {
                        "requests": {
                            "memory": format!("{request_memory}Mi"),
                            "cpu": format!("{request_cpu}m"),
                        },
                        "limits": {
                            "memory": format!("{memory}Mi"),
                            "cpu": format!("{cpu}m"),
                            "ephemeral-storage": "64Mi",
                        },
                    },
                    "volumeMounts": [{"name": "scratch", "mountPath": "/scratch"}],
                }],
                "volumes": [{"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}}],
            },
        }))
    }

    /// One runner pod as the cluster reports it (`kata.py:86-99`).
    ///
    /// A pod without this executor's labels is not ours: it is refused rather than reported, so
    /// a mislabelled or foreign pod can never satisfy `inspect` and be adopted or attached to.
    /// A pod without the two identity labels or an integer fence is refused for the same reason
    /// (the reference raises on the missing label; this returns the same denial as a value).
    pub fn record(pod: &KubePod) -> Result<Pod, BackendError> {
        let labels = pod
            .metadata
            .labels
            .as_ref()
            .ok_or(BackendError::Denied("the pod carries no executor labels"))?;
        if labels
            .get("app.kubernetes.io/managed-by")
            .map(String::as_str)
            != Some("mcp-executor")
        {
            return Err(BackendError::Denied(
                "the pod is not managed by this executor",
            ));
        }
        let run_id = labels
            .get("mcp.run-id")
            .ok_or(BackendError::Denied("the pod carries no run id"))?
            .clone();
        let fence = labels
            .get("mcp.fence")
            .ok_or(BackendError::Denied("the pod carries no fence"))?
            .parse::<i64>()
            .map_err(|_| BackendError::Denied("the pod's fence is not an integer"))?;
        let status = pod
            .status
            .as_ref()
            .ok_or(BackendError::Denied("the pod carries no status"))?;
        let phase = status
            .phase
            .clone()
            .ok_or(BackendError::Denied("the pod carries no phase"))?;
        // The reference reads the FIRST container status, whatever it is named.
        let exit_code = status
            .container_statuses
            .as_ref()
            .and_then(|statuses| statuses.first())
            .and_then(|status| status.state.as_ref())
            .and_then(|state| state.terminated.as_ref())
            .map(|terminated| terminated.exit_code);
        Ok(Pod {
            name: pod
                .metadata
                .name
                .clone()
                .ok_or(BackendError::Denied("the pod carries no name"))?,
            uid: pod
                .metadata
                .uid
                .clone()
                .ok_or(BackendError::Denied("the pod carries no uid"))?,
            run_id,
            fence,
            phase,
            exit_code,
        })
    }

    /// `stop`, with the confirmation interval as a parameter.
    ///
    /// Production always passes [`STOP_CONFIRM_INTERVAL`]; the parameter exists so a test can
    /// drive the reference's 20-attempt rule without sleeping five seconds.
    pub async fn stop_with_interval(
        &self,
        pod: &Pod,
        interval: Duration,
    ) -> Result<bool, BackendError> {
        let Some(current) = self.inspect(&pod.name).await? else {
            return Ok(true);
        };
        if current.uid != pod.uid || current.run_id != pod.run_id || current.fence != pod.fence {
            return Err(BackendError::Denied(
                "the runner pod is not the one this run recorded",
            ));
        }
        let params = DeleteParams::default()
            .preconditions(Preconditions {
                uid: Some(pod.uid.clone()),
                ..Preconditions::default()
            })
            .grace_period(0);
        match self.pods.delete(&pod.name, &params).await {
            Ok(_) => {}
            Err(kube::Error::Api(status)) if status.is_not_found() => {}
            Err(kube::Error::Api(_)) => {
                return Err(BackendError::Denied("the runner pod delete was refused"));
            }
            Err(error) => return Err(transport("delete the runner pod", error)),
        }
        for _ in 0..STOP_CONFIRM_ATTEMPTS {
            if self.inspect(&pod.name).await?.is_none() {
                return Ok(true);
            }
            tokio::time::sleep(interval).await;
        }
        Ok(false)
    }
}

#[async_trait]
impl Backend for Kata {
    async fn ready(&self) -> Result<(), BackendError> {
        let runtime_class = self
            .settings
            .kata_runtime_class
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(BackendError::Denied(
                "execution requires a Kata runtime class",
            ))?;
        if self
            .settings
            .runner_image_digest
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(BackendError::Denied(
                "execution requires a runner image digest",
            ));
        }
        // A resource-name scoped read of one cluster-scoped RuntimeClass: no discovery, no node,
        // secret or namespace management (`kata.py:180-188`).
        let api: Api<DynamicObject> = Api::all_with(self.client.clone(), &runtime_class_resource());
        match api.get_opt(runtime_class).await {
            Ok(Some(object)) => {
                let handler = object
                    .data
                    .get("handler")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if handler.is_empty() {
                    return Err(BackendError::Denied(
                        "the Kata RuntimeClass carries no handler",
                    ));
                }
            }
            Ok(None) => {
                return Err(BackendError::Denied("the Kata RuntimeClass is absent"));
            }
            Err(error) => return Err(transport("read the Kata RuntimeClass", error)),
        }
        self.list().await.map(|_| ())
    }

    async fn inspect(&self, name: &str) -> Result<Option<Pod>, BackendError> {
        match self.pods.get_opt(name).await {
            Ok(Some(pod)) => Self::record(&pod).map(Some),
            Ok(None) => Ok(None),
            Err(error) => Err(transport("read the runner pod", error)),
        }
    }

    async fn start(&self, row: &WorkerRow, limits: &ToolLimits) -> Result<Pod, BackendError> {
        let name = pod_name(&row.run.run_id, row.fence);
        let manifest = Self::pod_manifest(row, &self.settings, limits)?;
        let pod: KubePod = serde_json::from_value(manifest)
            .map_err(|_| BackendError::Denied("the runner pod manifest is invalid"))?;
        // An ambiguous create is resolved by exact deterministic name, never by launching a
        // second pod. Any failure — 409, 5xx, a timeout, a dropped connection — takes the same
        // path: inspect this name and adopt only a pod that is this run's.
        let adopted = match self.pods.create(&PostParams::default(), &pod).await {
            Ok(created) => Self::record(&created)?,
            Err(error) => {
                tracing::warn!(%name, %error, "runner pod create failed; resolving by name");
                self.inspect(&name).await?.ok_or(BackendError::Denied(
                    "the runner pod create failed and left no pod to adopt",
                ))?
            }
        };
        if adopted.run_id != row.run.run_id.to_string()
            || adopted.fence != row.fence
            || match &row.pod_uid {
                Some(uid) => uid != &adopted.uid,
                None => false,
            }
        {
            return Err(BackendError::Denied(
                "the runner pod does not belong to this run and fence",
            ));
        }
        Ok(adopted)
    }

    async fn attach(&self, pod: &Pod) -> Result<Box<dyn AttachChannel>, BackendError> {
        let current = self.inspect(&pod.name).await?.ok_or(BackendError::Denied(
            "the runner pod is gone or was replaced",
        ))?;
        if current.uid != pod.uid {
            return Err(BackendError::Denied(
                "the runner pod is gone or was replaced",
            ));
        }
        let params = AttachParams::default()
            .container(RUNNER_CONTAINER)
            .stdin(true)
            .stdout(true)
            .stderr(true)
            .tty(false);
        let process = self
            .pods
            .attach(&pod.name, &params)
            .await
            .map_err(|error| transport("attach to the runner", error))?;
        let channel: Box<dyn AttachChannel> = Box::new(KataAttach::new(process));
        Ok(channel)
    }

    async fn stop(&self, pod: &Pod) -> Result<bool, BackendError> {
        self.stop_with_interval(pod, STOP_CONFIRM_INTERVAL).await
    }

    async fn list(&self) -> Result<Vec<Pod>, BackendError> {
        let params = ListParams::default().labels(MANAGED_BY).limit(200);
        let list = self
            .pods
            .list(&params)
            .await
            .map_err(|error| transport("list the runner pods", error))?;
        // One page is the whole inventory: a continue token means the executor cannot see every
        // pod it owns, so it must not start another run (`kata.py:296-297`).
        if list
            .metadata
            .continue_
            .as_deref()
            .is_some_and(|token| !token.is_empty())
        {
            return Err(BackendError::Denied(
                "runner pod inventory exceeds capacity",
            ));
        }
        list.items.iter().map(Self::record).collect()
    }
}

/// One attached runner process, drained channel by channel.
///
/// `receive` returns only bytes that have **already arrived** (the reference's
/// `read_stdout(timeout=0)`):
///
/// * `Ok(Some((stdout, stderr)))` with either vector non-empty — those bytes.
/// * `Ok(Some((vec![], vec![])))` — the attach stream is still open but nothing has arrived yet.
///   This is the reference's `(b"", b"")`, and it is deliberately not `Ok(None)`: `None` is
///   reserved for a closed stream.
/// * `Ok(None)` — every channel reached EOF (the runner exited or the websocket ended).
/// * `Err(Transport)` — a real read failure.
///
/// A caller must not spin on the empty answer without yielding; the reference's controller
/// awaits `receive` and processes frames, which is the same loop.
pub struct KataAttach {
    /// The websocket pump. Dropping (or aborting) it ends the attach task.
    process: Option<AttachedProcess>,
    stdin: Option<WriteHalf<SimplexStream>>,
    stdout: Option<ReadHalf<SimplexStream>>,
    stderr: Option<ReadHalf<SimplexStream>>,
    /// Resolves when the attach stream closes (the reference's `is_open()` going false).
    ///
    /// It is needed because the pipes are `tokio::io::simplex` split halves: dropping the
    /// writer half does not close the stream (the halves share one `Arc`), so a read on an
    /// empty pipe stays pending rather than reporting EOF. The kube status receiver is the
    /// real closure signal, exactly as the websocket's open flag is in the reference.
    status: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// Set by [`AttachChannel::close`]; once closed, every receive answers `None`.
    closed: bool,
}

impl KataAttach {
    /// Take the three pipes from the attached process. Each is available only once.
    fn new(mut process: AttachedProcess) -> Self {
        let stdin = process.stdin();
        let stdout = process.stdout();
        let stderr = process.stderr();
        let status = process.take_status().map(|future| {
            let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let _ = future.await;
            });
            future
        });
        Self {
            process: Some(process),
            stdin,
            stdout,
            stderr,
            status,
            closed: false,
        }
    }

    /// A channel over caller-supplied pipes, with no websocket behind it.
    ///
    /// This exists so the buffered-read rules can be exercised over `tokio::io::simplex`
    /// without a handshake; production always goes through [`KataAttach::new`].
    pub fn from_streams(
        stdin: Option<WriteHalf<SimplexStream>>,
        stdout: Option<ReadHalf<SimplexStream>>,
        stderr: Option<ReadHalf<SimplexStream>>,
    ) -> Self {
        Self {
            process: None,
            stdin,
            stdout,
            stderr,
            status: None,
            closed: false,
        }
    }

    /// A channel whose closure is driven by `status`, for the buffered-read tests.
    pub fn from_streams_with_close(
        stdout: Option<ReadHalf<SimplexStream>>,
        stderr: Option<ReadHalf<SimplexStream>>,
        status: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Self {
        Self {
            process: None,
            stdin: None,
            stdout,
            stderr,
            status: Some(status),
            closed: false,
        }
    }
}

#[async_trait]
impl AttachChannel for KataAttach {
    async fn send(&mut self, data: &[u8]) -> Result<(), BackendError> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(BackendError::Denied("the runner attach has no stdin"));
        };
        // Frames are newline-delimited JSON bytes. The websocket pump splits them across its
        // internal pipe as it likes; the runner reassembles by newline, so no framing is lost.
        stdin
            .write_all(data)
            .await
            .map_err(|error| BackendError::Transport(format!("attach write: {error}")))?;
        stdin
            .flush()
            .await
            .map_err(|error| BackendError::Transport(format!("attach flush: {error}")))
    }

    async fn receive(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, BackendError> {
        let (stdout, stdout_eof) = drain_available(&mut self.stdout).await?;
        let (stderr, stderr_eof) = drain_available(&mut self.stderr).await?;
        // Buffered output always goes out before closure is reported: a runner's last frame
        // must not be lost to the status arriving first.
        if !stdout.is_empty() || !stderr.is_empty() {
            return Ok(Some((stdout, stderr)));
        }
        if let Some(status) = self.status.as_mut()
            && tokio::time::timeout(Duration::ZERO, status).await.is_ok()
        {
            self.status = None;
            self.closed = true;
        }
        if self.closed || (stdout_eof && stderr_eof) {
            return Ok(None);
        }
        Ok(Some((Vec::new(), Vec::new())))
    }

    async fn close(&mut self) {
        // Dropping the halves closes the pipes; aborting the pump stops the websocket task.
        self.closed = true;
        self.status = None;
        self.stdin = None;
        self.stdout = None;
        self.stderr = None;
        if let Some(process) = self.process.take() {
            process.abort();
        }
    }
}

/// Drain one channel's already-buffered bytes without blocking.
///
/// Each read is raced against a zero-duration deadline. Tokio polls the future first, so a read
/// with data ready completes and an empty-but-open pipe reports elapsed; a closed pipe reports
/// `Ok(0)`. The loop stops at the first empty poll, so a call never waits for the runner to
/// speak again — the reason the reference used `timeout=0` (blocking would hold the executor
/// past its deadline while the runner waits for an `api_result`).
///
/// Returns the bytes and whether the channel is at EOF. A missing channel counts as EOF.
async fn drain_available(
    reader: &mut Option<ReadHalf<SimplexStream>>,
) -> Result<(Vec<u8>, bool), BackendError> {
    let Some(reader) = reader.as_mut() else {
        return Ok((Vec::new(), true));
    };
    let mut collected = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        // The poll future is bound before the match so its borrow of `buffer` ends with this
        // statement; a match scrutinee would keep the temporary alive through the arms.
        let polled = tokio::time::timeout(Duration::ZERO, reader.read(&mut buffer)).await;
        match polled {
            Ok(Ok(0)) => return Ok((collected, true)),
            Ok(Ok(read)) => collected.extend_from_slice(&buffer[..read]),
            Ok(Err(error)) => {
                return Err(BackendError::Transport(format!("attach read: {error}")));
            }
            Err(_elapsed) => return Ok((collected, false)),
        }
    }
}

/// The `node.k8s.io/v1` `RuntimeClass` as a dynamic resource (`kata.py:182-185`).
fn runtime_class_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("node.k8s.io", "v1", "RuntimeClass"))
}

/// The run's snapshotted [`ToolManifest`], decoded from the authority member that carries it.
///
/// The member is a JSON **string** holding the model's own JSON (`row.rs`); a missing or
/// invalid snapshot is a denial, never a fallback to the live catalog.
fn snapshot_manifest(row: &WorkerRow) -> Result<ToolManifest, BackendError> {
    let raw = row
        .run
        .authority
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(BackendError::Denied(
            "the run's authority carries no manifest snapshot",
        ))?;
    serde_json::from_str(raw).map_err(|_| {
        BackendError::Denied("the run's manifest snapshot is not a valid tool manifest")
    })
}

/// A kube transport failure, with the operation that failed for the log line.
fn transport(operation: &str, error: kube::Error) -> BackendError {
    BackendError::Transport(format!("{operation}: {error}"))
}
