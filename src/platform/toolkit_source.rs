//! Platform toolkit sources: the repo tree under `toolkits/` as typed, version-less manifests.
//!
//! Ported from the reference `src/platform/toolkit_source.py`. Pure: no database, no network.
//! Layout:
//!
//! ```text
//! toolkits/_kit/kit.py                  stdlib helpers, copied into every package as `kit.py`
//! toolkits/<tk>/toolkit.json            {"toolkit_id", "name", "description"}
//! toolkits/<tk>/service.json            ServiceManifest without `version`
//! toolkits/<tk>/operations/<key>.json   OperationManifest without `version` and `service`
//! toolkits/<tk>/tools/<tool>/tool.json  ToolManifest fields except tenant_id, version,
//!                                       package_sha256, runner_image_digest;
//!                                       `allowed_operations` is a list of operation keys
//! toolkits/<tk>/tools/<tool>/*.py       package files (the package also gets kit.py, ops.py and
//!                                       toolkits/<tk>/shared/*.py)
//! ```
//!
//! A toolkit directory WITHOUT `service.json` is an EXTERNAL toolkit: no service, no operations,
//! no runner image. Its `tool.json` also carries `runtime` (not kata_python) and `target`; the
//! package is the tool directory's other files (at least one, e.g. README.md), with no kit.py or
//! ops.py.
//!
//! Versions are not in the source: the seed assigns them (content addressed). The models built
//! here carry the PLACEHOLDER version 1; the seed replaces it. [`package_files`] is the one
//! packager both the repository seed and the generic import use; it reproduces the reference's
//! Python `json.dumps(..., indent=2, sort_keys=True)` bytes for the generated `ops.py`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::builder::packaging::{self, OpRefs};
use crate::catalog::ids::PositiveVersion;
use crate::catalog::models::{ExactReference, OperationManifest, ServiceManifest};
use crate::catalog::package::PackageFile;

/// The directory holding the shared `kit.py`, never a toolkit itself.
pub const KIT_DIR: &str = "_kit";
/// The version every source-model carries; the seed assigns the real one by content.
pub const PLACEHOLDER_VERSION: u32 = 1;
/// The tool fields a `tool.json` may name (the reference's `TOOL_FIELDS`).
pub const TOOL_FIELDS: [&str; 14] = [
    "tool_id",
    "public_name",
    "operation",
    "description",
    "entrypoint",
    "input_schema",
    "result_schema",
    "context_schema",
    "limits",
    "effect",
    "allowed_operations",
    "operation_constraints",
    "runtime",
    "target",
];

/// Which packager a source uses: the repository tree (shared modules + kit.py + ops.py) or a
/// generic import bundle (its own files + the generated ops.py, no kit.py or shared modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageMode {
    /// `toolkits/<tk>/`: `shared/*.py` + the tool's files + `kit.py` + `ops.py`.
    Repository,
    /// A `ToolkitBundle` tool: its own files + `ops.py`.
    Bundle,
}

/// A refused source tree: the reference's `ValueError`, or a file/model failure it lets escape.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The reference's `ValueError` (`_load_tool`/`_load_toolkit`/`package_files` messages).
    #[error("{0}")]
    Invalid(String),
    /// A filesystem, JSON or manifest failure reading the tree (the reference's `OSError`,
    /// `JSONDecodeError` or Pydantic `ValidationError`). The path is named, never a content.
    #[error("{path}: {message}")]
    Source { path: String, message: String },
}

/// One tool of a toolkit, as the repository declares it (no tenant, version or digest yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSource {
    /// The tool directory's name (the seed's label component), or a bundle's public name.
    pub name: String,
    /// The `ToolManifest` fields the repository chose, `allowed_operations` already removed.
    pub fields: Map<String, Value>,
    /// Operation keys the tool may call, in the repository's order.
    pub op_keys: Vec<String>,
    /// The tool's own package files, in the loader's order.
    pub files: Vec<(String, String)>,
}

/// One toolkit of the repository tree, as the loader returns it.
#[derive(Debug, Clone)]
pub struct ToolkitSource {
    /// The toolkit directory's name, or a bundle's `toolkit.name`.
    pub name: String,
    /// `toolkit.json` verbatim (fields, not a validated manifest).
    pub toolkit: Map<String, Value>,
    /// The validated `service.json` as JSON, or `None` for an external toolkit.
    pub service: Option<Value>,
    /// `<key>: OperationManifest` as JSON, in the repository's (sorted) order.
    pub operations: Map<String, Value>,
    /// The toolkit's tools, in the repository's (sorted) or the bundle's order.
    pub tools: Vec<ToolSource>,
    /// `toolkits/_kit/kit.py`.
    pub kit: String,
    /// `toolkits/<tk>/shared/*.py`: modules every tool package of this toolkit also receives.
    pub shared: Vec<(String, String)>,
}

impl ToolkitSource {
    /// An external toolkit has no service, operations or runner image.
    pub fn external(&self) -> bool {
        self.service.is_none()
    }

    /// The tool with this directory (or public) name.
    pub fn tool(&self, name: &str) -> Option<&ToolSource> {
        self.tools.iter().find(|tool| tool.name == name)
    }
}

/// Load every toolkit under `root`, in the reference's order (directory name, `_kit` skipped).
pub fn load_all(root: &Path) -> Result<Vec<ToolkitSource>, LoadError> {
    let kit = read_text(&root.join(KIT_DIR).join("kit.py"))?;
    let mut sources = Vec::new();
    for path in entries(root)? {
        if path.file_name().and_then(|name| name.to_str()) == Some(KIT_DIR)
            || !path.is_dir()
            || !path.join("toolkit.json").is_file()
        {
            continue;
        }
        sources.push(load_toolkit(&path, &kit)?);
    }
    Ok(sources)
}

/// One toolkit directory.
fn load_toolkit(directory: &Path, kit: &str) -> Result<ToolkitSource, LoadError> {
    let name = directory_name(directory)?;
    let toolkit = read_object(&directory.join("toolkit.json"))?;
    if !directory.join("service.json").is_file() {
        let tools = load_tools(directory, &BTreeSet::new())?;
        if tools
            .iter()
            .any(|tool| runtime_name(&tool.fields) == "kata_python")
        {
            return Err(LoadError::Invalid(format!(
                "{name}: a toolkit without service.json is external-only"
            )));
        }
        return Ok(ToolkitSource {
            name,
            toolkit,
            service: None,
            operations: Map::new(),
            tools,
            kit: kit.to_owned(),
            shared: Vec::new(),
        });
    }
    let mut service_raw = read_object(&directory.join("service.json"))?;
    service_raw.insert("version".to_owned(), json!(PLACEHOLDER_VERSION));
    let service: ServiceManifest = serde_json::from_value(Value::Object(service_raw))
        .map_err(|error| source(format!("{name}/service.json"), error))?;
    let reference = ExactReference {
        id: service.service_id.clone(),
        version: one(),
    };
    let mut operations = Map::new();
    let operations_dir = directory.join("operations");
    if operations_dir.is_dir() {
        for path in entries(&operations_dir)? {
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let mut document = read_object(&path)?;
            document.insert(
                "service".to_owned(),
                json!({"id": reference.id.as_str(), "version": reference.version.get()}),
            );
            document.insert("version".to_owned(), json!(PLACEHOLDER_VERSION));
            let operation: OperationManifest = serde_json::from_value(Value::Object(document))
                .map_err(|error| source(display(&path), error))?;
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| LoadError::Invalid(format!("{name}: invalid operation file name")))?
                .to_owned();
            operations.insert(
                stem,
                serde_json::to_value(&operation).map_err(|error| source(display(&path), error))?,
            );
        }
    }
    let mut operation_ids = BTreeSet::new();
    for operation in operations.values() {
        let identity = operation
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !operation_ids.insert(identity.to_owned()) {
            return Err(LoadError::Invalid(format!(
                "{name}: duplicate operation_id"
            )));
        }
    }
    let keys: BTreeSet<String> = operations.keys().cloned().collect();
    let tools = load_tools(directory, &keys)?;
    let mut shared = Vec::new();
    let shared_dir = directory.join("shared");
    if shared_dir.is_dir() {
        for path in entries(&shared_dir)? {
            if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("py") {
                shared.push((file_name(&path)?, read_text(&path)?));
            }
        }
    }
    let service = serde_json::to_value(&service).map_err(|error| source(&name, error))?;
    Ok(ToolkitSource {
        name,
        toolkit,
        service: Some(service),
        operations,
        tools,
        kit: kit.to_owned(),
        shared,
    })
}

/// Every tool directory of one toolkit, in the reference's order.
fn load_tools(
    directory: &Path,
    operations: &BTreeSet<String>,
) -> Result<Vec<ToolSource>, LoadError> {
    let name = directory_name(directory)?;
    let tools_dir = directory.join("tools");
    let mut tools = Vec::new();
    for path in entries(&tools_dir)? {
        if path.join("tool.json").is_file() {
            tools.push(load_tool(&path, operations)?);
        }
    }
    let mut names = BTreeSet::new();
    for tool in &tools {
        let public_name = tool
            .fields
            .get("public_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !names.insert(public_name.to_owned()) {
            return Err(LoadError::Invalid(format!(
                "{name}: duplicate tool public_name"
            )));
        }
    }
    Ok(tools)
}

/// One tool directory.
fn load_tool(directory: &Path, operations: &BTreeSet<String>) -> Result<ToolSource, LoadError> {
    let name = directory_name(directory)?;
    let mut raw = read_object(&directory.join("tool.json"))?;
    let mut unknown: Vec<String> = raw
        .keys()
        .filter(|key| !TOOL_FIELDS.contains(&key.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        return Err(LoadError::Invalid(format!(
            "{name}/tool.json: unknown fields {}",
            python_list(&unknown)
        )));
    }
    let keys = match raw.remove("allowed_operations") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut keys = Vec::with_capacity(items.len());
            for item in items {
                let Value::String(key) = item else {
                    return Err(LoadError::Invalid(format!(
                        "{name}: allowed_operations unknown or duplicated: []"
                    )));
                };
                keys.push(key);
            }
            keys
        }
        Some(_) => {
            return Err(LoadError::Invalid(format!(
                "{name}: allowed_operations unknown or duplicated: []"
            )));
        }
    };
    let missing: Vec<String> = keys
        .iter()
        .filter(|key| !operations.contains(*key))
        .cloned()
        .collect();
    let duplicates = keys.iter().collect::<BTreeSet<_>>().len() != keys.len();
    if !missing.is_empty() || duplicates {
        return Err(LoadError::Invalid(format!(
            "{name}: allowed_operations unknown or duplicated: {}",
            python_list(&missing)
        )));
    }
    raw.entry("result_schema".to_owned())
        .or_insert_with(packaging::default_result_schema);
    raw.entry("context_schema".to_owned())
        .or_insert_with(packaging::no_context);
    if runtime_name(&raw) != "kata_python" {
        if !keys.is_empty() || raw.contains_key("entrypoint") {
            return Err(LoadError::Invalid(format!(
                "{name}: an external tool takes no operations or entrypoint"
            )));
        }
        let extra: Vec<PathBuf> = entries(directory)?
            .into_iter()
            .filter(|path| path.is_file() && file_name(path).ok().as_deref() != Some("tool.json"))
            .collect();
        if extra.is_empty() {
            return Err(LoadError::Invalid(format!(
                "{name}: an external tool needs a package file (README.md)"
            )));
        }
        let files = extra
            .iter()
            .map(|path| Ok((file_name(path)?, read_text(path)?)))
            .collect::<Result<Vec<_>, LoadError>>()?;
        return Ok(ToolSource {
            name,
            fields: raw,
            op_keys: keys,
            files,
        });
    }
    if raw.contains_key("target") {
        return Err(LoadError::Invalid(format!(
            "{name}: kata_python tools take no target"
        )));
    }
    raw.entry("entrypoint".to_owned())
        .or_insert_with(|| Value::String("tool:main".to_owned()));
    let python_files: Vec<PathBuf> = entries(directory)?
        .into_iter()
        .filter(|path| {
            path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("py")
        })
        .collect();
    let files = python_files
        .iter()
        .map(|path| Ok((file_name(path)?, read_text(path)?)))
        .collect::<Result<Vec<_>, LoadError>>()?;
    Ok(ToolSource {
        name,
        fields: raw,
        op_keys: keys,
        files,
    })
}

/// The reference's `package_files`: the tool's files plus the host files, sorted by path.
///
/// Repository toolkits receive the shared modules, `kit.py` (the tree's copy) and the generated
/// `ops.py`; external toolkits receive only their own files; a bundle receives its own files
/// plus `ops.py` (a bundle supplies its own `kit.py`, if any).
pub fn package_files(
    toolkit: &ToolkitSource,
    tool: &ToolSource,
    refs: &OpRefs,
    mode: PackageMode,
) -> Result<Vec<PackageFile>, LoadError> {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    if mode == PackageMode::Bundle {
        for (path, content) in &tool.files {
            files.insert(path.clone(), content.clone());
        }
        files.insert("ops.py".to_owned(), ops_source(&tool.op_keys, refs));
        return Ok(files.into_iter().map(package_file).collect());
    }
    if toolkit.external() {
        for (path, content) in &tool.files {
            files.insert(path.clone(), content.clone());
        }
        return Ok(files.into_iter().map(package_file).collect());
    }
    let shared: BTreeSet<&str> = toolkit
        .shared
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    let own: BTreeSet<&str> = tool.files.iter().map(|(name, _)| name.as_str()).collect();
    let names: BTreeSet<&str> = shared.union(&own).copied().collect();
    let clash: Vec<&str> = ["kit.py", "ops.py"]
        .into_iter()
        .filter(|host| names.contains(host))
        .collect();
    if !clash.is_empty() || !shared.is_disjoint(&own) {
        return Err(LoadError::Invalid(format!(
            "{}: package file name collision {}",
            tool.name,
            python_list(
                &clash
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>()
            )
        )));
    }
    for (path, content) in &toolkit.shared {
        files.insert(path.clone(), content.clone());
    }
    for (path, content) in &tool.files {
        files.insert(path.clone(), content.clone());
    }
    files.insert("kit.py".to_owned(), toolkit.kit.clone());
    files.insert("ops.py".to_owned(), ops_source(&tool.op_keys, refs));
    Ok(files.into_iter().map(package_file).collect())
}

fn package_file((path, content): (String, String)) -> PackageFile {
    PackageFile { path, content }
}

/// The generated `ops.py`: `json.dumps(table, indent=2, sort_keys=True)` bytes, exactly.
pub fn ops_source(op_keys: &[String], refs: &OpRefs) -> String {
    let mut table: BTreeMap<&str, (String, u32)> = BTreeMap::new();
    for key in op_keys {
        if let Some((identity, version)) = refs.get(key) {
            table.insert(key.as_str(), (identity.as_str().to_owned(), version.get()));
        }
    }
    let mut text = String::from("# Generated: operation id and exact version per key.\nOPS = ");
    if table.is_empty() {
        text.push_str("{}");
    } else {
        text.push('{');
        for (index, (key, (identity, version))) in table.iter().enumerate() {
            if index > 0 {
                text.push(',');
            }
            text.push_str("\n  ");
            write_json_string(&mut text, key);
            text.push_str(": [\n    ");
            write_json_string(&mut text, identity);
            text.push_str(",\n    ");
            let _ = write!(text, "{version}");
            text.push_str("\n  ]");
        }
        text.push_str("\n}");
    }
    text.push('\n');
    text
}

/// `json.dumps(text, ensure_ascii=True)` for one string.
fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if !control.is_ascii() || control.is_ascii_control() => {
                let code = control as u32;
                if code <= 0xFFFF {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let adjusted = code - 0x1_0000;
                    let high = 0xD800 + (adjusted >> 10);
                    let low = 0xDC00 + (adjusted & 0x3FF);
                    let _ = write!(out, "\\u{high:04x}\\u{low:04x}");
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The reference's `raw.get("runtime", "kata_python")`, including a non-string value meaning
/// "not kata_python" exactly as Python's comparison would.
fn runtime_name(fields: &Map<String, Value>) -> &str {
    match fields.get("runtime") {
        None => "kata_python",
        Some(Value::String(name)) => name,
        Some(_) => "",
    }
}

/// A string list as Python's `repr` renders it (`['a', 'b']`), for the reference's messages.
fn python_list(values: &[String]) -> String {
    let entries: Vec<String> = values.iter().map(|value| format!("'{value}'")).collect();
    format!("[{}]", entries.join(", "))
}

/// A positive version 1.
fn one() -> PositiveVersion {
    PositiveVersion::new(1).expect("one is a positive version")
}

fn source(path: impl std::fmt::Display, error: impl std::fmt::Display) -> LoadError {
    LoadError::Source {
        path: path.to_string(),
        message: error.to_string(),
    }
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn directory_name(directory: &Path) -> Result<String, LoadError> {
    directory
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| source(display(directory), "invalid directory name"))
}

fn file_name(path: &Path) -> Result<String, LoadError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| source(display(path), "invalid file name"))
}

/// The directory entries, sorted by path (the reference's `sorted(p.iterdir())`).
fn entries(directory: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let mut paths = Vec::new();
    let reader = std::fs::read_dir(directory).map_err(|error| source(display(directory), error))?;
    for entry in reader {
        paths.push(
            entry
                .map_err(|error| source(display(directory), error))?
                .path(),
        );
    }
    paths.sort();
    Ok(paths)
}

fn read_text(path: &Path) -> Result<String, LoadError> {
    std::fs::read_to_string(path).map_err(|error| source(display(path), error))
}

fn read_object(path: &Path) -> Result<Map<String, Value>, LoadError> {
    let text = read_text(path)?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(LoadError::Source {
            path: display(path),
            message: "expected a JSON object".to_owned(),
        }),
        Err(error) => Err(source(display(path), error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ids::Uuid7;

    fn reference(operation_id: &str, version: u64) -> (String, (Uuid7, PositiveVersion)) {
        (
            operation_id.to_owned(),
            (
                Uuid7::new(operation_id).unwrap(),
                PositiveVersion::new(version).unwrap(),
            ),
        )
    }

    #[test]
    fn ops_py_matches_the_builder_packager() {
        let mut refs = OpRefs::new();
        for (key, value) in [
            reference("01900000-0000-7000-8000-000000000001", 1),
            reference("01900000-0000-7000-8000-000000000002", 3),
        ] {
            refs.insert(key, value);
        }
        // The table's keys ARE the pinned operation ids: the packager hands `ops_source` the
        // refs it was given, and a key the caller names but never pinned is simply absent.
        let keys: Vec<String> = refs.keys().cloned().collect();
        // The builder's packager writes the same Python `json.dumps` text; an empty package makes
        // it emit only kit.py and ops.py.
        let built = packaging::build_package(&[], &refs);
        let ops = built
            .iter()
            .find(|file| file.path == "ops.py")
            .expect("the packager emits ops.py");
        assert_eq!(ops_source(&keys, &refs), ops.content);
        // The table is keyed by the keys the caller names; the packager hands it the refs, so
        // it emits every pinned operation — an empty key list is an empty table, not a refusal.
        assert_eq!(
            ops_source(&[], &refs),
            "# Generated: operation id and exact version per key.\nOPS = {}\n"
        );
        assert_eq!(
            ops_source(&keys, &refs),
            ops_source(&keys, &refs),
            "the same inputs are deterministic"
        );
    }

    #[test]
    fn the_repository_tree_loads() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolkits");
        let sources = load_all(&root).expect("the repository toolkits load");
        let names: Vec<&str> = sources.iter().map(|source| source.name.as_str()).collect();
        assert_eq!(names, vec!["coding", "fr"]);
        let coding = sources
            .iter()
            .find(|source| source.name == "coding")
            .unwrap();
        assert!(!coding.external());
        assert_eq!(coding.operations.len(), 39);
        assert_eq!(coding.tools.len(), 11);
        assert_eq!(coding.shared.len(), 1);
        let read = coding.tool("coding_read_file").expect("the read tool");
        assert_eq!(read.op_keys, vec!["workspace_status", "read_file"]);
        assert_eq!(read.fields["entrypoint"], "tool:main");
        let fr = sources.iter().find(|source| source.name == "fr").unwrap();
        assert!(fr.external());
        assert_eq!(fr.tools.len(), 3);
        assert_eq!(fr.tools[0].files[0].0, "README.md");
        assert!(fr.tools.iter().all(|tool| tool.op_keys.is_empty()));
    }

    #[test]
    fn packages_carry_shared_kit_and_ops_in_path_order() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolkits");
        let sources = load_all(&root).expect("the repository toolkits load");
        let coding = sources
            .iter()
            .find(|source| source.name == "coding")
            .unwrap();
        let read = coding.tool("coding_read_file").unwrap();
        let mut refs = OpRefs::new();
        for key in &read.op_keys {
            refs.insert(
                key.clone(),
                (
                    Uuid7::new("01900000-0000-7000-8000-000000000001").unwrap(),
                    PositiveVersion::new(2).unwrap(),
                ),
            );
        }
        let files = package_files(coding, read, &refs, PackageMode::Repository).unwrap();
        let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, vec!["coding.py", "kit.py", "ops.py", "tool.py"]);
        assert_eq!(files[0].content, coding.shared[0].1);
        assert_eq!(files[1].content, coding.kit);
        assert!(files[2].content.contains("\"read_file\""));
        assert!(
            files[2]
                .content
                .contains("01900000-0000-7000-8000-000000000001")
        );
        let external = sources.iter().find(|source| source.name == "fr").unwrap();
        let get = &external.tools[0];
        let files = package_files(external, get, &OpRefs::new(), PackageMode::Repository).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "README.md");
    }
}
