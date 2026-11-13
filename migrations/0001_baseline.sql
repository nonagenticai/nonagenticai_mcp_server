-- pg_dump emits functions before the tables their bodies reference; the dump
-- disables body validation for exactly that reason. SET LOCAL keeps the setting
-- inside sqlx's migration transaction instead of leaking it to the pool.
SET LOCAL check_function_bodies = false;

--
-- PostgreSQL database dump
--


-- Dumped from database version 18.6 (Ubuntu 18.6-1.pgdg24.04+2)
-- Dumped by pg_dump version 18.6 (Ubuntu 18.6-1.pgdg24.04+2)


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


--
-- Name: mcp_access_complete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_access_complete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE data jsonb; b public.mcp_bindings; p public.mcp_credential_profiles;
BEGIN
    IF TG_OP='DELETE' THEN data=to_jsonb(OLD); ELSE data=to_jsonb(NEW); END IF;
    IF TG_ARGV[0]='binding' THEN
        SELECT * INTO b FROM public.mcp_bindings WHERE tenant_id=(data->>'tenant_id')::uuid AND binding_id=(data->>'binding_id')::uuid;
        IF (SELECT count(*) FROM public.mcp_binding_tools WHERE tenant_id=b.tenant_id AND binding_id=b.binding_id) <> jsonb_array_length(b.tools)
           OR (SELECT count(*) FROM public.mcp_binding_toolkits WHERE tenant_id=b.tenant_id AND binding_id=b.binding_id) <> jsonb_array_length(b.spec->'toolkits')
           OR EXISTS (SELECT 1 FROM public.mcp_binding_tools r WHERE r.tenant_id=b.tenant_id AND r.binding_id=b.binding_id
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(b.tools) e WHERE e->>'public_name'=r.public_name
                    AND e->'tool'->>'tenant_id'=r.owner_tenant_id::text AND e->'tool'->>'id'=r.tool_id::text AND (e->'tool'->>'version')::integer=r.version))
           OR EXISTS (SELECT 1 FROM public.mcp_binding_toolkits r WHERE r.tenant_id=b.tenant_id AND r.binding_id=b.binding_id
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(b.spec->'toolkits') e
                    WHERE e->>'id'=r.toolkit_id::text AND (e->>'version')::integer=r.version
                    -- An omitted owner is the binding's own tenant (ToolkitReference).
                    AND coalesce(e->>'tenant_id',b.tenant_id::text)=r.owner_tenant_id::text)) THEN
            RAISE EXCEPTION 'incomplete binding selection' USING ERRCODE='23514';
        END IF;
    ELSE
        SELECT * INTO p FROM public.mcp_credential_profiles WHERE tenant_id=(data->>'tenant_id')::uuid AND profile_id=(data->>'profile_id')::uuid;
        IF (SELECT count(*) FROM public.mcp_credential_refs WHERE tenant_id=p.tenant_id AND profile_id=p.profile_id) <> jsonb_array_length(p.manifest->'services')+1
           OR EXISTS (SELECT 1 FROM public.mcp_credential_refs r WHERE r.tenant_id=p.tenant_id AND r.profile_id=p.profile_id
               AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements((p.manifest->'services') || jsonb_build_array((p.manifest->'gateway') || '{"service":"__gateway"}'::jsonb)) e
                   WHERE e->>'service'=r.service_key AND e->>'alias'=r.alias AND e->>'license_id'=r.license_id::text AND e->>'app_key'=r.app_key)) THEN
            RAISE EXCEPTION 'incomplete credential references' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;


--
-- Name: mcp_access_generation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_access_generation() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    UPDATE public.mcp_catalog_state SET generation=generation+1 WHERE singleton;
    RETURN NULL;
END $$;


--
-- Name: mcp_builder_guard_tenant(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_guard_tenant(p_tenant uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF p_tenant IS NULL OR p_tenant = public.mcp_platform_tenant() THEN
        RAISE EXCEPTION 'the platform tenant cannot use the builder' USING ERRCODE = 'MB004';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('builder:' || p_tenant::text));
END $$;




--
-- Name: mcp_operation_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_operation_versions (
    operation_id uuid NOT NULL,
    version integer NOT NULL,
    service_id uuid NOT NULL,
    service_version integer NOT NULL,
    manifest jsonb NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_operation_versions_check CHECK (((manifest ?& ARRAY['operation_id'::text, 'service'::text]) AND ((manifest ->> 'operation_id'::text) = (operation_id)::text) AND (((manifest ->> 'version'::text))::integer = version))),
    CONSTRAINT mcp_operation_versions_check1 CHECK (((((manifest -> 'service'::text) ->> 'id'::text) = (service_id)::text) AND ((((manifest -> 'service'::text) ->> 'version'::text))::integer = service_version))),
    CONSTRAINT mcp_operation_versions_manifest_check CHECK (((jsonb_typeof(manifest) = 'object'::text) AND (manifest ?& ARRAY['schema_version'::text, 'version'::text]) AND ((manifest ->> 'schema_version'::text) = '1'::text))),
    CONSTRAINT mcp_operation_versions_operation_id_v7 CHECK ((((get_byte(uuid_send(operation_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(operation_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_operation_versions_service_id_v7 CHECK ((((get_byte(uuid_send(service_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(service_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_operation_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'disabled'::text, 'retired'::text]))),
    CONSTRAINT mcp_operation_versions_version_check CHECK ((version > 0))
);


--
-- Name: mcp_builder_operation_create(uuid, jsonb, text, jsonb, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_operation_create(p_tenant uuid, p_manifest jsonb, p_op_key text, p_actor jsonb, p_max_operations integer) RETURNS public.mcp_operation_versions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE op_id uuid := (p_manifest->>'operation_id')::uuid;
        sid uuid := (p_manifest->'service'->>'id')::uuid;
        sver integer := (p_manifest->'service'->>'version')::integer;
        nxt integer; svc_status text; keyed uuid; r public.mcp_operation_versions;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    SELECT v.status INTO svc_status FROM public.mcp_service_versions v
        JOIN public.mcp_services s USING (service_id)
        WHERE v.service_id = sid AND v.version = sver AND s.owner_tenant_id = p_tenant;
    IF NOT FOUND THEN RAISE EXCEPTION 'service not found' USING ERRCODE = 'MB002'; END IF;
    IF svc_status NOT IN ('draft','published') THEN
        RAISE EXCEPTION 'service version is not usable' USING ERRCODE = 'MB001';
    END IF;
    SELECT coalesce(max(version),0) + 1 INTO nxt FROM public.mcp_operation_versions
        WHERE operation_id = op_id;
    IF (p_manifest->>'version')::integer <> nxt THEN
        RAISE EXCEPTION 'operation version must append' USING ERRCODE = 'MB001';
    END IF;
    IF nxt = 1 THEN
        IF p_op_key IS NULL THEN
            RAISE EXCEPTION 'a new operation needs an operation key' USING ERRCODE = '23514';
        END IF;
        IF (SELECT count(*) FROM public.mcp_operation_keys k
            JOIN public.mcp_services s USING (service_id)
            WHERE s.owner_tenant_id = p_tenant) >= p_max_operations THEN
            RAISE EXCEPTION 'operation quota exceeded' USING ERRCODE = 'MB003';
        END IF;
        INSERT INTO public.mcp_operation_keys(service_id,op_key,operation_id) VALUES (sid,p_op_key,op_id);
    ELSE
        SELECT service_id INTO keyed FROM public.mcp_operation_keys WHERE operation_id = op_id;
        IF keyed IS DISTINCT FROM sid OR (p_op_key IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM public.mcp_operation_keys WHERE operation_id = op_id AND op_key = p_op_key)) THEN
            RAISE EXCEPTION 'operation key or service mismatch' USING ERRCODE = 'MB001';
        END IF;
    END IF;
    INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,service_version,
        manifest,created_by,updated_by)
        VALUES (op_id,nxt,sid,sver,p_manifest,p_actor,p_actor) RETURNING * INTO r;
    RETURN r;
END $$;


--
-- Name: mcp_builder_publish(uuid, jsonb, jsonb, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_publish(p_tenant uuid, p_services jsonb, p_operations jsonb, p_actor jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE e jsonb;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    FOR e IN SELECT * FROM jsonb_array_elements(p_services) LOOP
        PERFORM public.mcp_builder_set_status(p_tenant,'service',(e->>'id')::uuid,(e->>'version')::integer,'published',p_actor);
    END LOOP;
    FOR e IN SELECT * FROM jsonb_array_elements(p_operations) LOOP
        PERFORM public.mcp_builder_set_status(p_tenant,'operation',(e->>'id')::uuid,(e->>'version')::integer,'published',p_actor);
    END LOOP;
END $$;


--
-- Name: mcp_service_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_service_versions (
    service_id uuid NOT NULL,
    version integer NOT NULL,
    manifest jsonb NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_service_versions_check CHECK (((manifest ? 'service_id'::text) AND ((manifest ->> 'service_id'::text) = (service_id)::text) AND (((manifest ->> 'version'::text))::integer = version))),
    CONSTRAINT mcp_service_versions_manifest_check CHECK (((jsonb_typeof(manifest) = 'object'::text) AND (manifest ?& ARRAY['schema_version'::text, 'version'::text]) AND ((manifest ->> 'schema_version'::text) = '1'::text))),
    CONSTRAINT mcp_service_versions_service_id_v7 CHECK ((((get_byte(uuid_send(service_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(service_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_service_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'disabled'::text, 'retired'::text]))),
    CONSTRAINT mcp_service_versions_version_check CHECK ((version > 0))
);


--
-- Name: mcp_builder_service_append(uuid, jsonb, bigint, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_service_append(p_tenant uuid, p_manifest jsonb, p_expected_revision bigint, p_actor jsonb) RETURNS public.mcp_service_versions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE sid uuid := (p_manifest->>'service_id')::uuid; s public.mcp_services;
        nxt integer; first_manifest jsonb; r public.mcp_service_versions;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    SELECT * INTO s FROM public.mcp_services
        WHERE service_id = sid AND owner_tenant_id = p_tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'service not found' USING ERRCODE = 'MB002'; END IF;
    SELECT max(version) + 1 INTO nxt FROM public.mcp_service_versions WHERE service_id = sid;
    SELECT manifest INTO first_manifest FROM public.mcp_service_versions
        WHERE service_id = sid AND version = 1;
    IF s.revision <> p_expected_revision OR (p_manifest->>'version')::integer <> nxt
       OR p_manifest->>'service_key' <> s.service_key
       OR p_manifest->>'destination_alias' <> first_manifest->>'destination_alias'
       OR p_manifest->>'auth_adapter' <> 'source' THEN
        RAISE EXCEPTION 'service identity, revision or version mismatch' USING ERRCODE = 'MB001';
    END IF;
    UPDATE public.mcp_services SET revision = revision + 1 WHERE service_id = sid;
    INSERT INTO public.mcp_service_versions(service_id,version,manifest,created_by,updated_by)
        VALUES (sid,nxt,p_manifest,p_actor,p_actor) RETURNING * INTO r;
    RETURN r;
END $$;


--
-- Name: mcp_builder_service_create(uuid, jsonb, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_service_create(p_tenant uuid, p_manifest jsonb, p_actor jsonb) RETURNS public.mcp_service_versions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE sid uuid := (p_manifest->>'service_id')::uuid; r public.mcp_service_versions;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    IF (p_manifest->>'version')::integer <> 1 OR p_manifest->>'auth_adapter' <> 'source' THEN
        RAISE EXCEPTION 'a builder service starts at version 1 with the source adapter'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.mcp_sources WHERE owner_tenant_id = p_tenant
        AND source_key = p_manifest->>'destination_alias' AND status = 'active') THEN
        RAISE EXCEPTION 'source not found' USING ERRCODE = 'MB002';
    END IF;
    IF EXISTS (SELECT 1 FROM public.mcp_services s
        JOIN public.mcp_service_versions v ON v.service_id = s.service_id AND v.version = 1
        WHERE s.owner_tenant_id = p_tenant
          AND v.manifest->>'destination_alias' = p_manifest->>'destination_alias') THEN
        RAISE EXCEPTION 'this source already has a service' USING ERRCODE = 'MB001';
    END IF;
    INSERT INTO public.mcp_services(service_id,service_key,owner_tenant_id,created_by)
        VALUES (sid,p_manifest->>'service_key',p_tenant,p_actor);
    INSERT INTO public.mcp_service_versions(service_id,version,manifest,created_by,updated_by)
        VALUES (sid,1,p_manifest,p_actor,p_actor) RETURNING * INTO r;
    RETURN r;
END $$;


--
-- Name: mcp_builder_set_status(uuid, text, uuid, integer, text, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_set_status(p_tenant uuid, p_kind text, p_id uuid, p_version integer, p_status text, p_actor jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    IF p_status NOT IN ('published','disabled','retired') THEN
        RAISE EXCEPTION 'invalid lifecycle state' USING ERRCODE = '23514';
    END IF;
    IF p_kind = 'service' THEN
        IF NOT EXISTS (SELECT 1 FROM public.mcp_services WHERE service_id = p_id AND owner_tenant_id = p_tenant) THEN
            RAISE EXCEPTION 'service not found' USING ERRCODE = 'MB002';
        END IF;
        UPDATE public.mcp_service_versions SET status = p_status, updated_by = p_actor,
            updated_at = clock_timestamp() WHERE service_id = p_id AND version = p_version;
    ELSIF p_kind = 'operation' THEN
        IF NOT EXISTS (SELECT 1 FROM public.mcp_operation_versions o
            JOIN public.mcp_services s USING (service_id)
            WHERE o.operation_id = p_id AND o.version = p_version AND s.owner_tenant_id = p_tenant) THEN
            RAISE EXCEPTION 'operation not found' USING ERRCODE = 'MB002';
        END IF;
        UPDATE public.mcp_operation_versions SET status = p_status, updated_by = p_actor,
            updated_at = clock_timestamp() WHERE operation_id = p_id AND version = p_version;
    ELSE
        RAISE EXCEPTION 'unknown kind' USING ERRCODE = '23514';
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'version not found' USING ERRCODE = 'MB002'; END IF;
END $$;


--
-- Name: mcp_platform_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_platform_tenant() RETURNS uuid
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT '01900000-0000-7000-8000-00000000f001'::uuid $$;


--
-- Name: mcp_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_sources (
    source_id uuid NOT NULL,
    source_key text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    base_url text NOT NULL,
    allow_internal_http boolean DEFAULT false NOT NULL,
    auth jsonb NOT NULL,
    token_ciphertext bytea,
    token_set_at timestamp with time zone,
    idempotency_header text,
    ca_file text,
    max_request_bytes integer,
    max_response_bytes integer,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    owner_tenant_id uuid DEFAULT public.mcp_platform_tenant() NOT NULL,
    spec_path text,
    CONSTRAINT mcp_sources_auth_check CHECK (((jsonb_typeof(auth) = 'object'::text) AND ((auth ->> 'kind'::text) = ANY (ARRAY['licence'::text, 'none'::text, 'static_bearer'::text, 'static_header'::text, 'query_param'::text, 'basic'::text, 'oauth2_client_credentials'::text])))),
    CONSTRAINT mcp_sources_base_url_check CHECK (((char_length(base_url) >= 8) AND (char_length(base_url) <= 512))),
    CONSTRAINT mcp_sources_ca_file_check CHECK ((char_length(ca_file) <= 512)),
    CONSTRAINT mcp_sources_check1 CHECK (((token_ciphertext IS NULL) = (token_set_at IS NULL))),
    CONSTRAINT mcp_sources_idempotency_header_check CHECK ((idempotency_header = ANY (ARRAY['Idempotency-Key'::text, 'X-Idempotency-Key'::text]))),
    CONSTRAINT mcp_sources_max_request_bytes_check CHECK ((max_request_bytes > 0)),
    CONSTRAINT mcp_sources_max_response_bytes_check CHECK ((max_response_bytes > 0)),
    CONSTRAINT mcp_sources_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_sources_source_id_check CHECK ((uuid_extract_version(source_id) = 7)),
    CONSTRAINT mcp_sources_source_key_check CHECK ((source_key ~ '^[a-z][a-z0-9_]{0,63}$'::text)),
    CONSTRAINT mcp_sources_spec_path_check CHECK (((spec_path IS NULL) OR ((spec_path ~ '^/[A-Za-z0-9._~/-]{0,255}$'::text) AND (spec_path !~ '(^|/)\.{1,2}(/|$)'::text) AND (spec_path !~ '//'::text)))),
    CONSTRAINT mcp_sources_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT mcp_sources_tenant_https CHECK (((owner_tenant_id = public.mcp_platform_tenant()) OR ((base_url ~~ 'https://%'::text) AND (NOT allow_internal_http) AND (ca_file IS NULL)))),
    CONSTRAINT mcp_sources_token_ciphertext_check CHECK (((octet_length(token_ciphertext) >= 29) AND (octet_length(token_ciphertext) <= 4124))),
    CONSTRAINT mcp_sources_token_presence CHECK ((((auth ->> 'kind'::text) = ANY (ARRAY['licence'::text, 'none'::text])) = (token_ciphertext IS NULL)))
);


--
-- Name: mcp_builder_source_create(uuid, uuid, text, text, jsonb, bytea, text, text, integer, integer, jsonb, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_source_create(p_tenant uuid, p_source_id uuid, p_key text, p_base_url text, p_auth jsonb, p_token bytea, p_spec_path text, p_idempotency_header text, p_max_request_bytes integer, p_max_response_bytes integer, p_actor jsonb, p_max_sources integer) RETURNS public.mcp_sources
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE r public.mcp_sources;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    IF (SELECT count(*) FROM public.mcp_sources
        WHERE owner_tenant_id = p_tenant AND status = 'active') >= p_max_sources THEN
        RAISE EXCEPTION 'source quota exceeded' USING ERRCODE = 'MB003';
    END IF;
    INSERT INTO public.mcp_sources(source_id,owner_tenant_id,source_key,base_url,allow_internal_http,
        auth,token_ciphertext,token_set_at,spec_path,idempotency_header,ca_file,max_request_bytes,
        max_response_bytes,created_by,updated_by)
    VALUES (p_source_id,p_tenant,p_key,p_base_url,false,p_auth,p_token,
        CASE WHEN p_token IS NULL THEN NULL ELSE clock_timestamp() END,p_spec_path,
        p_idempotency_header,NULL,p_max_request_bytes,p_max_response_bytes,p_actor,p_actor)
    RETURNING * INTO r;
    INSERT INTO public.mcp_source_events(source_id,owner_tenant_id,source_key,revision,event,actor)
        VALUES (r.source_id,r.owner_tenant_id,r.source_key,r.revision,'created',p_actor);
    RETURN r;
END $$;


--
-- Name: mcp_builder_source_set_secret(uuid, text, bigint, bytea, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_source_set_secret(p_tenant uuid, p_key text, p_expected_revision bigint, p_token bytea, p_actor jsonb) RETURNS public.mcp_sources
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE cur public.mcp_sources; r public.mcp_sources;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    SELECT * INTO cur FROM public.mcp_sources
        WHERE owner_tenant_id = p_tenant AND source_key = p_key FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'source not found' USING ERRCODE = 'MB002'; END IF;
    IF cur.revision <> p_expected_revision THEN
        RAISE EXCEPTION 'source revision mismatch' USING ERRCODE = 'MB001';
    END IF;
    IF cur.auth->>'kind' IN ('licence','none') OR p_token IS NULL THEN
        RAISE EXCEPTION 'this source carries no stored secret' USING ERRCODE = '23514';
    END IF;
    UPDATE public.mcp_sources SET revision = revision + 1, token_ciphertext = p_token,
        token_set_at = clock_timestamp(), updated_by = p_actor, updated_at = clock_timestamp()
        WHERE source_id = cur.source_id RETURNING * INTO r;
    INSERT INTO public.mcp_source_events(source_id,owner_tenant_id,source_key,revision,event,actor)
        VALUES (r.source_id,r.owner_tenant_id,r.source_key,r.revision,'token_set',p_actor);
    RETURN r;
END $$;


--
-- Name: mcp_builder_source_set_status(uuid, text, bigint, text, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_source_set_status(p_tenant uuid, p_key text, p_expected_revision bigint, p_status text, p_actor jsonb) RETURNS public.mcp_sources
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE cur public.mcp_sources; r public.mcp_sources;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    IF p_status NOT IN ('active','disabled') THEN
        RAISE EXCEPTION 'invalid source status' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO cur FROM public.mcp_sources
        WHERE owner_tenant_id = p_tenant AND source_key = p_key FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'source not found' USING ERRCODE = 'MB002'; END IF;
    IF cur.revision <> p_expected_revision OR cur.status = p_status THEN
        RAISE EXCEPTION 'source revision mismatch or already in that state' USING ERRCODE = 'MB001';
    END IF;
    UPDATE public.mcp_sources SET revision = revision + 1, status = p_status,
        updated_by = p_actor, updated_at = clock_timestamp()
        WHERE source_id = cur.source_id RETURNING * INTO r;
    INSERT INTO public.mcp_source_events(source_id,owner_tenant_id,source_key,revision,event,actor)
        VALUES (r.source_id,r.owner_tenant_id,r.source_key,r.revision,
            CASE WHEN p_status = 'disabled' THEN 'disabled' ELSE 'enabled' END,p_actor);
    RETURN r;
END $$;


--
-- Name: mcp_builder_source_update(uuid, text, bigint, text, jsonb, bytea, text, text, integer, integer, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_source_update(p_tenant uuid, p_key text, p_expected_revision bigint, p_base_url text, p_auth jsonb, p_token bytea, p_spec_path text, p_idempotency_header text, p_max_request_bytes integer, p_max_response_bytes integer, p_actor jsonb) RETURNS public.mcp_sources
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE cur public.mcp_sources; r public.mcp_sources;
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    SELECT * INTO cur FROM public.mcp_sources
        WHERE owner_tenant_id = p_tenant AND source_key = p_key FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'source not found' USING ERRCODE = 'MB002'; END IF;
    IF cur.revision <> p_expected_revision THEN
        RAISE EXCEPTION 'source revision mismatch' USING ERRCODE = 'MB001';
    END IF;
    UPDATE public.mcp_sources SET revision = revision + 1, base_url = p_base_url, auth = p_auth,
        token_ciphertext = CASE WHEN p_auth->>'kind' IN ('licence','none') THEN NULL
                                WHEN p_token IS NOT NULL THEN p_token ELSE token_ciphertext END,
        token_set_at = CASE WHEN p_auth->>'kind' IN ('licence','none') THEN NULL
                            WHEN p_token IS NOT NULL THEN clock_timestamp() ELSE token_set_at END,
        spec_path = p_spec_path, idempotency_header = p_idempotency_header,
        max_request_bytes = p_max_request_bytes, max_response_bytes = p_max_response_bytes,
        updated_by = p_actor, updated_at = clock_timestamp()
        WHERE source_id = cur.source_id RETURNING * INTO r;
    INSERT INTO public.mcp_source_events(source_id,owner_tenant_id,source_key,revision,event,actor)
        VALUES (r.source_id,r.owner_tenant_id,r.source_key,r.revision,'updated',p_actor);
    RETURN r;
END $$;


--
-- Name: mcp_builder_spec_put(uuid, uuid, text, integer, jsonb, integer, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_builder_spec_put(p_tenant uuid, p_source_id uuid, p_sha256 text, p_bytes integer, p_document jsonb, p_keep integer, p_max_total bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    PERFORM public.mcp_builder_guard_tenant(p_tenant);
    IF p_keep NOT BETWEEN 1 AND 10 THEN
        RAISE EXCEPTION 'spec retention outside bounds' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.mcp_sources
        WHERE source_id = p_source_id AND owner_tenant_id = p_tenant) THEN
        RAISE EXCEPTION 'source not found' USING ERRCODE = 'MB002';
    END IF;
    INSERT INTO public.mcp_source_specs(owner_tenant_id,source_id,sha256,bytes,document)
        VALUES (p_tenant,p_source_id,p_sha256,p_bytes,p_document)
        ON CONFLICT (source_id,sha256) DO UPDATE SET fetched_at = clock_timestamp();
    DELETE FROM public.mcp_source_specs WHERE source_id = p_source_id AND sha256 NOT IN (
        SELECT sha256 FROM public.mcp_source_specs WHERE source_id = p_source_id
        ORDER BY fetched_at DESC, sha256 LIMIT p_keep);
    -- Per-tenant storage cap, counted after pruning, under the tenant advisory lock taken by the
    -- guard above; raising rolls the insert back.
    IF p_max_total < 1 OR (SELECT COALESCE(sum(bytes), 0) FROM public.mcp_source_specs
                           WHERE owner_tenant_id = p_tenant) > p_max_total THEN
        RAISE EXCEPTION 'spec storage quota exceeded' USING ERRCODE = 'MB003';
    END IF;
END $$;


--
-- Name: mcp_bump_generation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_bump_generation() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF TG_TABLE_NAME IN ('mcp_tool_shares','mcp_service_grants') THEN
        UPDATE public.mcp_catalog_state SET generation = generation + 1 WHERE singleton;
        RETURN NULL;
    END IF;
    IF (to_jsonb(NEW)->>'status') IS DISTINCT FROM (to_jsonb(OLD)->>'status') OR
       (to_jsonb(NEW)->>'retired') IS DISTINCT FROM (to_jsonb(OLD)->>'retired') THEN
        UPDATE public.mcp_catalog_state SET generation = generation + 1 WHERE singleton;
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_check_operation_reference(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_check_operation_reference() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE o public.mcp_operation_versions;
BEGIN
    SELECT * INTO o FROM public.mcp_operation_versions
        WHERE operation_id = NEW.operation_id AND version = NEW.operation_version;
    -- A missing operation is the foreign key's error to raise.
    IF FOUND AND NOT public.mcp_tenant_may_use_service(NEW.tenant_id, o.service_id, o.service_version) THEN
        RAISE EXCEPTION 'operation service is not available to this tenant' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_check_package_complete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_check_package_complete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE files bigint; operations bigint;
BEGIN
    SELECT count(*) INTO files FROM public.mcp_tool_version_files
        WHERE tenant_id = NEW.tenant_id AND tool_id = NEW.tool_id AND version = NEW.version;
    SELECT count(*) INTO operations FROM public.mcp_tool_version_operations
        WHERE tenant_id = NEW.tenant_id AND tool_id = NEW.tool_id AND version = NEW.version;
    IF files <> NEW.file_count OR operations <> NEW.operation_count OR
        operations <> jsonb_array_length(NEW.manifest->'allowed_operations') THEN
        RAISE EXCEPTION 'incomplete version snapshot' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.mcp_tool_version_operations r
        WHERE r.tenant_id = NEW.tenant_id AND r.tool_id = NEW.tool_id AND r.version = NEW.version
        AND NOT NEW.manifest->'allowed_operations' @> jsonb_build_array(
            jsonb_build_object('id',r.operation_id::text,'version',r.operation_version))
    ) THEN
        RAISE EXCEPTION 'manifest/reference mismatch' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_check_publication(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_check_publication() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE dependency record; retired_parent boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'draft' THEN
            RAISE EXCEPTION 'new snapshots must be drafts' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status <> 'published' OR OLD.status = 'published' THEN RETURN NEW; END IF;
    IF TG_TABLE_NAME = 'mcp_operation_versions' THEN
        SELECT status INTO dependency FROM public.mcp_service_versions
            WHERE service_id = NEW.service_id AND version = NEW.service_version FOR SHARE;
        IF dependency.status <> 'published' THEN
            RAISE EXCEPTION 'service dependency is not published' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'mcp_tool_versions' THEN
        SELECT retired INTO retired_parent FROM public.mcp_tools
            WHERE tenant_id = NEW.tenant_id AND tool_id = NEW.tool_id FOR SHARE;
        IF retired_parent THEN
            RAISE EXCEPTION 'tool identity is retired' USING ERRCODE = '23514';
        END IF;
        FOR dependency IN
            SELECT o.status AS operation_status,s.status AS service_status,
                   public.mcp_tenant_may_use_service(NEW.tenant_id,o.service_id,o.service_version) AS allowed
            FROM public.mcp_tool_version_operations r
            JOIN public.mcp_operation_versions o ON (o.operation_id,o.version)=(r.operation_id,r.operation_version)
            JOIN public.mcp_service_versions s ON (s.service_id,s.version)=(o.service_id,o.service_version)
            WHERE r.tenant_id=NEW.tenant_id AND r.tool_id=NEW.tool_id AND r.version=NEW.version
            ORDER BY o.operation_id,o.version FOR SHARE OF o,s
        LOOP
            IF dependency.operation_status <> 'published' OR dependency.service_status <> 'published' THEN
                RAISE EXCEPTION 'catalog dependency is not published' USING ERRCODE = '23514';
            END IF;
            IF NOT dependency.allowed THEN
                RAISE EXCEPTION 'catalog dependency is not available to this tenant' USING ERRCODE = '23514';
            END IF;
        END LOOP;
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_expire_run_payloads(integer, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_expire_run_payloads(retention_days integer, batch_size integer) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE expired integer;
BEGIN
    IF retention_days NOT BETWEEN 1 AND 365 OR batch_size NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'retention outside bounds';
    END IF;
    WITH candidates AS (
        SELECT r.run_id FROM public.mcp_runs r
        WHERE r.payload_expired_at IS NULL
          AND r.finished_at<clock_timestamp()-retention_days*interval '1 day'
          AND r.status IN ('succeeded','failed','cancelled','timed_out','interrupted')
          AND r.worker_id IS NULL
          AND NOT EXISTS(SELECT 1 FROM public.mcp_execution_slots s WHERE s.run_id=r.run_id)
          AND NOT EXISTS(SELECT 1 FROM public.mcp_api_permits p WHERE p.run_id=r.run_id)
          AND NOT EXISTS(SELECT 1 FROM public.mcp_run_api_calls a WHERE a.run_id=r.run_id AND a.status='intent')
        ORDER BY r.finished_at,r.run_id LIMIT batch_size FOR UPDATE OF r SKIP LOCKED
    )
    UPDATE public.mcp_runs r SET inputs='{}',authority='{}',profile_snapshot='{}',result=NULL,
        payload_expired_at=clock_timestamp() FROM candidates c WHERE r.run_id=c.run_id;
    GET DIAGNOSTICS expired=ROW_COUNT;
    RETURN expired;
END $$;


--
-- Name: mcp_guard_access_event(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_access_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN RAISE EXCEPTION 'access events are append only' USING ERRCODE='23514'; END $$;


--
-- Name: mcp_guard_access_update(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_access_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'access history cannot be deleted' USING ERRCODE='23514'; END IF;
    IF NEW.revision <> OLD.revision+1 OR NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'access revision conflict' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME='mcp_bindings' THEN
        IF (to_jsonb(NEW)-ARRAY['revision','token_sha256','spec','tools','enabled','revoked','expires_at','credential_profile_id','updated_by','updated_at']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['revision','token_sha256','spec','tools','enabled','revoked','expires_at','credential_profile_id','updated_by','updated_at']) OR
           (OLD.revoked AND NOT NEW.revoked) THEN
            RAISE EXCEPTION 'immutable binding identity or revoked binding' USING ERRCODE='23514';
        END IF;
    ELSIF (to_jsonb(NEW)-ARRAY['revision','manifest','updated_by','updated_at']) IS DISTINCT FROM
          (to_jsonb(OLD)-ARRAY['revision','manifest','updated_by','updated_at']) THEN
        RAISE EXCEPTION 'immutable profile identity' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_binding_ensure(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_binding_ensure() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'binding ensures cannot be deleted' USING ERRCODE='23514';
    END IF;
    IF NEW.ensure_id <> OLD.ensure_id OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.product <> OLD.product OR NEW.created_by <> OLD.created_by
       OR NEW.created_at <> OLD.created_at OR NEW.revision <> OLD.revision+1 THEN
        RAISE EXCEPTION 'binding ensure identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_children(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_children() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE v public.mcp_tool_versions;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'version children cannot be changed or deleted' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO v FROM public.mcp_tool_versions
        WHERE tenant_id = NEW.tenant_id AND tool_id = NEW.tool_id AND version = NEW.version FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant-owned version not found' USING ERRCODE = '23503';
    END IF;
    IF v.status <> 'draft' OR v.creation_tx <> pg_current_xact_id()::text THEN
        RAISE EXCEPTION 'children must be created atomically with draft snapshot' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_execution_journal(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_execution_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='DELETE' OR TG_TABLE_NAME='mcp_run_events' THEN RAISE EXCEPTION 'execution history is immutable'; END IF;
    IF (to_jsonb(NEW)-ARRAY['status','finished_at','http_status','duration_ms','reason','error_excerpt']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['status','finished_at','http_status','duration_ms','reason','error_excerpt']) OR OLD.status<>'intent' OR
       NEW.status NOT IN ('succeeded','failed','outcome_unknown') OR NEW.finished_at IS NULL THEN
       RAISE EXCEPTION 'journal intent is immutable; only its outcome may be finalized';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'catalog identity cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(OLD) - ARRAY['revision','retired']) IS DISTINCT FROM
       (to_jsonb(NEW) - ARRAY['revision','retired']) OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'identity immutable; revision must advance once' USING ERRCODE = '23514';
    END IF;
    IF to_jsonb(OLD)->>'retired' = 'true' AND to_jsonb(NEW)->>'retired' <> 'true' THEN
        RAISE EXCEPTION 'retired identity cannot be enabled' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_operation_key(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_operation_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'operation keys are append-only' USING ERRCODE = '23514';
    END IF;
    -- The operation's versions, if any exist yet, must belong to the keyed service.
    IF EXISTS (SELECT 1 FROM public.mcp_operation_versions
               WHERE operation_id = NEW.operation_id AND service_id <> NEW.service_id) THEN
        RAISE EXCEPTION 'operation belongs to another service' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_run(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_run() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'run history is immutable'; END IF;
    IF TG_OP='UPDATE' AND NEW.payload_expired_at IS NOT NULL AND OLD.payload_expired_at IS NULL THEN
        IF current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.mcp_runs'::regclass)
           OR OLD.status NOT IN ('succeeded','failed','cancelled','timed_out','interrupted')
           OR OLD.finished_at IS NULL OR OLD.worker_id IS NOT NULL
           OR EXISTS(SELECT 1 FROM public.mcp_execution_slots WHERE run_id=OLD.run_id)
           OR EXISTS(SELECT 1 FROM public.mcp_api_permits WHERE run_id=OLD.run_id)
           OR EXISTS(SELECT 1 FROM public.mcp_run_api_calls WHERE run_id=OLD.run_id AND status='intent')
           OR NEW.inputs<>'{}'::jsonb OR NEW.authority<>'{}'::jsonb
           OR NEW.profile_snapshot<>'{}'::jsonb OR NEW.result IS NOT NULL
           OR (to_jsonb(NEW)-ARRAY['inputs','authority','profile_snapshot','result','payload_expired_at'])
              IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['inputs','authority','profile_snapshot','result','payload_expired_at'])
        THEN RAISE EXCEPTION 'invalid payload expiration'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.runtime IS DISTINCT FROM OLD.runtime THEN RAISE EXCEPTION 'run runtime is immutable'; END IF;
    -- An external reference only grows: keys can be added (fr's project id arrives after the
    -- start approval), never changed or removed.
    IF OLD.external_ref IS NOT NULL AND (NEW.external_ref IS NULL OR NOT NEW.external_ref @> OLD.external_ref) THEN
        RAISE EXCEPTION 'external reference only grows';
    END IF;
    IF NEW.payload_expired_at IS DISTINCT FROM OLD.payload_expired_at THEN
        RAISE EXCEPTION 'payload expiration is final';
    END IF;
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'run history is immutable'; END IF;
    IF (to_jsonb(NEW)-ARRAY['status','start_deadline','deadline','started_at','finished_at',
        'worker_id','fence','lease_until','heartbeat_at','pod_name','pod_uid','cancel_requested',
        'api_calls','result','error','external_ref','status_message']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['status','start_deadline','deadline','started_at','finished_at',
        'worker_id','fence','lease_until','heartbeat_at','pod_name','pod_uid','cancel_requested',
        'api_calls','result','error','external_ref','status_message']) THEN RAISE EXCEPTION 'run snapshot is immutable'; END IF;
    IF OLD.cancel_requested AND NOT NEW.cancel_requested THEN RAISE EXCEPTION 'cancellation is final'; END IF;
    IF NEW.fence<OLD.fence THEN RAISE EXCEPTION 'fence cannot decrease'; END IF;
    IF NEW.status<>OLD.status AND NOT (
        (OLD.status='queued' AND NEW.status IN ('starting','cancelled','timed_out','failed')) OR
        (OLD.status='starting' AND NEW.status IN ('running','cancelling','failed','timed_out','interrupted')) OR
        (OLD.status='starting' AND NEW.status='queued' AND OLD.pod_name IS NULL AND OLD.started_at IS NULL AND OLD.api_calls=0) OR
        (OLD.status='running' AND NEW.status IN ('succeeded','failed','timed_out','interrupted','cancelling')) OR
        (OLD.status='cancelling' AND NEW.status IN ('cancelled','interrupted'))
    ) THEN RAISE EXCEPTION 'invalid execution transition'; END IF;
    IF OLD.status IN ('succeeded','failed','cancelled','timed_out','interrupted') AND
       (NEW.result IS DISTINCT FROM OLD.result OR NEW.error IS DISTINCT FROM OLD.error) THEN
       RAISE EXCEPTION 'terminal result is immutable'; END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_service_grant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_service_grant() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'grants are replaced, not updated' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' AND NOT EXISTS (SELECT 1 FROM public.mcp_services
        WHERE service_id = NEW.service_id AND owner_tenant_id = public.mcp_platform_tenant()) THEN
        RAISE EXCEPTION 'only platform services can be granted' USING ERRCODE = '23514';
    END IF;
    RETURN COALESCE(NEW, OLD);
END $$;


--
-- Name: mcp_guard_snapshot(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'catalog history cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(OLD) - ARRAY['status','updated_by','updated_at']) IS DISTINCT FROM
       (to_jsonb(NEW) - ARRAY['status','updated_by','updated_at']) THEN
        RAISE EXCEPTION 'version content is immutable; append a snapshot' USING ERRCODE = '23514';
    END IF;
    IF NEW.status <> OLD.status AND NOT (
        (OLD.status = 'draft' AND NEW.status IN ('published','disabled','retired')) OR
        (OLD.status = 'published' AND NEW.status IN ('disabled','retired')) OR
        (OLD.status = 'disabled' AND NEW.status = 'retired')
    ) THEN
        RAISE EXCEPTION 'invalid lifecycle transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_source(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_source() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'sources cannot be deleted; disable them' USING ERRCODE = '23514';
    END IF;
    IF NEW.source_id IS DISTINCT FROM OLD.source_id OR NEW.source_key IS DISTINCT FROM OLD.source_key
       OR NEW.owner_tenant_id IS DISTINCT FROM OLD.owner_tenant_id
       OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'source identity immutable; revision must advance once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_guard_tool_call_audit(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_tool_call_audit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'tool call audit is append-only' USING ERRCODE='23514';
END $$;


--
-- Name: mcp_guard_toolkit_child(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_guard_toolkit_child() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE v public.mcp_toolkit_versions;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'toolkit children are immutable' USING ERRCODE='23514'; END IF;
    SELECT * INTO v FROM public.mcp_toolkit_versions
        WHERE tenant_id=NEW.tenant_id AND toolkit_id=NEW.toolkit_id AND version=NEW.version FOR UPDATE;
    IF v.status <> 'draft' OR v.creation_tx <> pg_current_xact_id()::text THEN
        RAISE EXCEPTION 'toolkit children must be atomic' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_lock_access_tool(uuid, uuid, uuid, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_lock_access_tool(request_tenant uuid, owner_tenant uuid, selected_tool uuid, selected_version integer) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE d record;
BEGIN
    IF request_tenant <> owner_tenant THEN
        PERFORM 1 FROM public.mcp_tool_shares WHERE owner_tenant_id=owner_tenant
            AND tool_id=selected_tool AND grantee_tenant_id=request_tenant FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'tool not shared' USING ERRCODE='23514'; END IF;
    END IF;
    SELECT v.status,t.retired INTO d FROM public.mcp_tool_versions v JOIN public.mcp_tools t USING(tenant_id,tool_id)
        WHERE v.tenant_id=owner_tenant AND v.tool_id=selected_tool AND v.version=selected_version FOR SHARE OF v,t;
    IF NOT FOUND OR d.status <> 'published' OR d.retired THEN
        RAISE EXCEPTION 'tool unavailable' USING ERRCODE='23514';
    END IF;
    FOR d IN SELECT o.status AS op,s.status AS service FROM public.mcp_tool_version_operations r
        JOIN public.mcp_operation_versions o ON (o.operation_id,o.version)=(r.operation_id,r.operation_version)
        JOIN public.mcp_service_versions s ON (s.service_id,s.version)=(o.service_id,o.service_version)
        WHERE r.tenant_id=owner_tenant AND r.tool_id=selected_tool AND r.version=selected_version
        ORDER BY o.operation_id,o.version FOR SHARE OF o,s
    LOOP
        IF d.op <> 'published' OR d.service <> 'published' THEN
            RAISE EXCEPTION 'operation unavailable' USING ERRCODE='23514';
        END IF;
    END LOOP;
END $$;


--
-- Name: mcp_lock_execution_authority(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_lock_execution_authority() RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE value bigint;
BEGIN
    SELECT generation INTO value FROM public.mcp_catalog_state WHERE singleton FOR SHARE;
    RETURN value;
END $$;


--
-- Name: mcp_tenant_may_use_service(uuid, uuid, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_tenant_may_use_service(p_tenant uuid, p_service uuid, p_version integer) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.mcp_services s
        WHERE s.service_id = p_service AND (
            s.owner_tenant_id = p_tenant
            OR (s.owner_tenant_id = public.mcp_platform_tenant() AND (
                EXISTS (SELECT 1 FROM public.mcp_service_grants g
                        WHERE g.service_id = s.service_id AND g.grantee_tenant_id = p_tenant)
                OR NOT EXISTS (
                    SELECT 1 FROM public.mcp_service_versions v
                    JOIN public.mcp_sources src ON src.owner_tenant_id = s.owner_tenant_id
                        AND src.source_key = v.manifest->>'destination_alias'
                    WHERE v.service_id = s.service_id AND v.version = p_version
                      AND src.auth->>'kind' <> 'licence'))))
    )
$$;


--
-- Name: mcp_toolkit_complete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_toolkit_complete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (SELECT count(*) FROM public.mcp_toolkit_version_tools WHERE tenant_id=NEW.tenant_id AND toolkit_id=NEW.toolkit_id AND version=NEW.version)
        <> jsonb_array_length(NEW.tools) OR
       (SELECT count(*) FROM public.mcp_toolkit_inclusions WHERE tenant_id=NEW.tenant_id AND toolkit_id=NEW.toolkit_id AND version=NEW.version)
        <> jsonb_array_length(NEW.manifest->'includes') THEN
        RAISE EXCEPTION 'incomplete toolkit snapshot' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT 1 FROM public.mcp_toolkit_version_tools t
        WHERE t.tenant_id=NEW.tenant_id AND t.toolkit_id=NEW.toolkit_id AND t.version=NEW.version
        AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.tools) e
            WHERE e->>'public_name'=t.public_name AND e->'tool'->>'tenant_id'=t.owner_tenant_id::text
                AND e->'tool'->>'id'=t.tool_id::text AND (e->'tool'->>'version')::integer=t.tool_version)) THEN
        RAISE EXCEPTION 'toolkit reference mismatch' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT 1 FROM public.mcp_toolkit_inclusions r
        WHERE r.tenant_id=NEW.tenant_id AND r.toolkit_id=NEW.toolkit_id AND r.version=NEW.version
        AND NOT NEW.manifest->'includes' @> jsonb_build_array(jsonb_build_object('id',r.included_id::text,'version',r.included_version))) THEN
        RAISE EXCEPTION 'toolkit inclusion mismatch' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mcp_toolkit_publication(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mcp_toolkit_publication() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE d record;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status <> 'draft' THEN RAISE EXCEPTION 'new toolkit must be draft' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.status <> 'published' OR OLD.status='published' THEN RETURN NEW; END IF;
    FOR d IN SELECT v.status,t.retired,r.owner_tenant_id,r.tool_id
        FROM public.mcp_toolkit_version_tools r JOIN public.mcp_tool_versions v
        ON (v.tenant_id,v.tool_id,v.version)=(r.owner_tenant_id,r.tool_id,r.tool_version)
        JOIN public.mcp_tools t ON (t.tenant_id,t.tool_id)=(v.tenant_id,v.tool_id)
        WHERE r.tenant_id=NEW.tenant_id AND r.toolkit_id=NEW.toolkit_id AND r.version=NEW.version
        ORDER BY v.tenant_id,v.tool_id,v.version FOR SHARE OF v,t
    LOOP
        IF d.status <> 'published' OR d.retired OR (d.owner_tenant_id <> NEW.tenant_id AND NOT EXISTS (
            SELECT 1 FROM public.mcp_tool_shares WHERE owner_tenant_id=d.owner_tenant_id AND tool_id=d.tool_id AND grantee_tenant_id=NEW.tenant_id
        )) THEN RAISE EXCEPTION 'unavailable toolkit tool' USING ERRCODE='23514'; END IF;
    END LOOP;
    FOR d IN SELECT v.status FROM public.mcp_toolkit_inclusions r JOIN public.mcp_toolkit_versions v
        ON (v.tenant_id,v.toolkit_id,v.version)=(r.tenant_id,r.included_id,r.included_version)
        WHERE r.tenant_id=NEW.tenant_id AND r.toolkit_id=NEW.toolkit_id AND r.version=NEW.version
        ORDER BY v.toolkit_id,v.version FOR SHARE OF v
    LOOP
        IF d.status <> 'published' THEN RAISE EXCEPTION 'unavailable toolkit inclusion' USING ERRCODE='23514'; END IF;
    END LOOP;
    RETURN NEW;
END $$;


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: mcp_access_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_access_events (
    event_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    subject text NOT NULL,
    license_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    action text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    artifact_version integer,
    CONSTRAINT mcp_access_events_artifact_version_check CHECK ((artifact_version > 0)),
    CONSTRAINT mcp_access_events_entity_id_v7 CHECK ((((get_byte(uuid_send(entity_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(entity_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_access_events_event_id_v7 CHECK ((((get_byte(uuid_send(event_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(event_id), 8) >> 6) = 2))),
    CONSTRAINT tool_event_version_required CHECK (((action <> ALL (ARRAY['tool.created'::text, 'tool.version_created'::text, 'tool.published'::text, 'tool.disabled'::text, 'tool.retired'::text])) OR (artifact_version IS NOT NULL)))
);


--
-- Name: mcp_api_permits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_api_permits (
    permit_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    fence bigint NOT NULL,
    service_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT mcp_api_permits_permit_id_check CHECK ((uuid_extract_version(permit_id) = 7))
);


--
-- Name: mcp_api_rate_windows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_api_rate_windows (
    tenant_id uuid NOT NULL,
    service_id uuid NOT NULL,
    window_start timestamp with time zone NOT NULL,
    calls integer NOT NULL,
    CONSTRAINT mcp_api_rate_windows_calls_check CHECK ((calls > 0))
);


--
-- Name: mcp_binding_ensures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_binding_ensures (
    ensure_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    product text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    gateway_license_id uuid,
    credential_profile_id uuid,
    binding_id uuid,
    toolkits jsonb DEFAULT '[]'::jsonb NOT NULL,
    skipped jsonb DEFAULT '[]'::jsonb NOT NULL,
    token_issued_at timestamp with time zone,
    created_by text NOT NULL,
    updated_by text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_binding_ensures_check CHECK (((binding_id IS NULL) = (token_issued_at IS NULL))),
    CONSTRAINT mcp_binding_ensures_check1 CHECK (((binding_id IS NULL) OR ((gateway_license_id IS NOT NULL) AND (credential_profile_id IS NOT NULL)))),
    CONSTRAINT mcp_binding_ensures_created_by_check CHECK (((length(created_by) >= 1) AND (length(created_by) <= 256))),
    CONSTRAINT mcp_binding_ensures_ensure_id_check CHECK ((uuid_extract_version(ensure_id) = 7)),
    CONSTRAINT mcp_binding_ensures_product_check CHECK ((product ~ '^[a-z][a-z0-9-]{0,63}$'::text)),
    CONSTRAINT mcp_binding_ensures_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_binding_ensures_skipped_check CHECK (((jsonb_typeof(skipped) = 'array'::text) AND (jsonb_array_length(skipped) <= 32))),
    CONSTRAINT mcp_binding_ensures_toolkits_check CHECK (((jsonb_typeof(toolkits) = 'array'::text) AND (jsonb_array_length(toolkits) <= 32))),
    CONSTRAINT mcp_binding_ensures_updated_by_check CHECK (((length(updated_by) >= 1) AND (length(updated_by) <= 256)))
);


--
-- Name: mcp_binding_toolkits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_binding_toolkits (
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    toolkit_id uuid NOT NULL,
    version integer NOT NULL,
    owner_tenant_id uuid NOT NULL,
    CONSTRAINT mcp_binding_toolkits_binding_id_v7 CHECK ((((get_byte(uuid_send(binding_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(binding_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_binding_toolkits_owner CHECK (((owner_tenant_id = tenant_id) OR (owner_tenant_id = public.mcp_platform_tenant()))),
    CONSTRAINT mcp_binding_toolkits_toolkit_id_v7 CHECK ((((get_byte(uuid_send(toolkit_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(toolkit_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_binding_tools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_binding_tools (
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    owner_tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    version integer NOT NULL,
    public_name text NOT NULL,
    CONSTRAINT mcp_binding_tools_binding_id_v7 CHECK ((((get_byte(uuid_send(binding_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(binding_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_binding_tools_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_bindings (
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    gateway_license_id uuid NOT NULL,
    credential_profile_id uuid NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    token_sha256 text NOT NULL,
    spec jsonb NOT NULL,
    tools jsonb NOT NULL,
    enabled boolean NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_bindings_binding_id_v7 CHECK ((((get_byte(uuid_send(binding_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(binding_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_bindings_check CHECK (((spec ?& ARRAY['schema_version'::text, 'credential_profile_id'::text, 'context'::text, 'expires_at'::text, 'enabled'::text]) AND ((spec ->> 'schema_version'::text) = '1'::text) AND ((spec ->> 'credential_profile_id'::text) = (credential_profile_id)::text) AND (((spec -> 'context'::text) ->> 'tenant_id'::text) = (tenant_id)::text) AND (((spec ->> 'enabled'::text))::boolean = enabled) AND (((spec ->> 'expires_at'::text))::timestamp with time zone = expires_at))),
    CONSTRAINT mcp_bindings_credential_profile_id_v7 CHECK ((((get_byte(uuid_send(credential_profile_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(credential_profile_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_bindings_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_bindings_token_sha256_check CHECK ((token_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT mcp_bindings_tools_check CHECK (((jsonb_typeof(tools) = 'array'::text) AND (jsonb_array_length(tools) <= 128)))
);


--
-- Name: mcp_catalog_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_catalog_state (
    singleton boolean DEFAULT true NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    CONSTRAINT mcp_catalog_state_generation_check CHECK ((generation >= 0)),
    CONSTRAINT mcp_catalog_state_singleton_check CHECK (singleton)
);


--
-- Name: mcp_credential_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_credential_profiles (
    tenant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    name text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    manifest jsonb NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_credential_profiles_check CHECK (((manifest ?& ARRAY['schema_version'::text, 'tenant_id'::text, 'profile_id'::text, 'gateway'::text, 'services'::text]) AND ((manifest ->> 'schema_version'::text) = '1'::text) AND ((manifest ->> 'tenant_id'::text) = (tenant_id)::text) AND ((manifest ->> 'profile_id'::text) = (profile_id)::text))),
    CONSTRAINT mcp_credential_profiles_profile_id_v7 CHECK ((((get_byte(uuid_send(profile_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(profile_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_credential_profiles_revision_check CHECK ((revision > 0))
);


--
-- Name: mcp_credential_refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_credential_refs (
    tenant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    service_key text NOT NULL,
    alias text NOT NULL,
    license_id uuid NOT NULL,
    app_key text NOT NULL,
    CONSTRAINT mcp_credential_refs_alias_check CHECK ((alias ~ '^[a-z][a-z0-9_]{0,63}$'::text)),
    CONSTRAINT mcp_credential_refs_profile_id_v7 CHECK ((((get_byte(uuid_send(profile_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(profile_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_execution_slots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_execution_slots (
    slot_id integer NOT NULL,
    run_id uuid,
    quarantined boolean DEFAULT false NOT NULL,
    draining boolean DEFAULT false NOT NULL,
    CONSTRAINT mcp_execution_slots_slot_id_check CHECK ((slot_id > 0))
);


--
-- Name: mcp_operation_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_operation_keys (
    service_id uuid NOT NULL,
    op_key text NOT NULL,
    operation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_operation_keys_op_key_check CHECK ((op_key ~ '^[a-z][a-z0-9_]{0,63}$'::text)),
    CONSTRAINT mcp_operation_keys_operation_id_check CHECK ((uuid_extract_version(operation_id) = 7))
);


--
-- Name: mcp_protocol_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_protocol_sessions (
    session_sha256 text NOT NULL,
    tenant_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    gateway_license_id uuid NOT NULL,
    token_sha256 text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT mcp_protocol_sessions_binding_id_v7 CHECK ((((get_byte(uuid_send(binding_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(binding_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_protocol_sessions_session_sha256_check CHECK ((session_sha256 ~ '^[a-f0-9]{64}$'::text))
);


--
-- Name: mcp_run_activity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_run_activity (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    seq bigint NOT NULL,
    kind text NOT NULL,
    text text NOT NULL,
    severity text NOT NULL,
    source_ref text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_run_activity_kind_check CHECK ((kind = ANY (ARRAY['phase'::text, 'started'::text, 'approval_requested'::text, 'approval_closed'::text, 'refused'::text, 'failed'::text, 'delivered'::text]))),
    CONSTRAINT mcp_run_activity_severity_check CHECK ((severity = ANY (ARRAY['info'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text]))),
    CONSTRAINT mcp_run_activity_source_ref_check CHECK (((source_ref IS NULL) OR (char_length(source_ref) <= 200))),
    CONSTRAINT mcp_run_activity_text_check CHECK ((char_length(text) <= 512))
);


--
-- Name: mcp_run_activity_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mcp_run_activity_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mcp_run_activity_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mcp_run_activity_seq_seq OWNED BY public.mcp_run_activity.seq;


--
-- Name: mcp_run_api_calls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_run_api_calls (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence integer NOT NULL,
    operation_id uuid NOT NULL,
    operation_version integer NOT NULL,
    request_hash text NOT NULL,
    idempotency_key text,
    license_id uuid NOT NULL,
    effect text NOT NULL,
    status text DEFAULT 'intent'::text NOT NULL,
    started_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    finished_at timestamp with time zone,
    method text,
    path text,
    http_status integer,
    duration_ms integer,
    reason text,
    error_excerpt text,
    CONSTRAINT mcp_run_api_calls_duration_ms_check CHECK ((duration_ms >= 0)),
    CONSTRAINT mcp_run_api_calls_effect_check CHECK ((effect = ANY (ARRAY['read_only'::text, 'writes'::text]))),
    CONSTRAINT mcp_run_api_calls_error_excerpt_check CHECK ((char_length(error_excerpt) <= 2048)),
    CONSTRAINT mcp_run_api_calls_http_status_check CHECK (((http_status >= 100) AND (http_status <= 599))),
    CONSTRAINT mcp_run_api_calls_method_check CHECK ((method = ANY (ARRAY['GET'::text, 'POST'::text, 'PUT'::text, 'PATCH'::text, 'DELETE'::text]))),
    CONSTRAINT mcp_run_api_calls_path_check CHECK ((char_length(path) <= 1024)),
    CONSTRAINT mcp_run_api_calls_reason_check CHECK ((reason = ANY (ARRAY['ssrf_blocked'::text, 'redirect'::text, 'status'::text, 'too_large'::text, 'schema_mismatch'::text, 'auth_failed'::text, 'timeout'::text, 'transport'::text]))),
    CONSTRAINT mcp_run_api_calls_request_hash_check CHECK ((request_hash ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT mcp_run_api_calls_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT mcp_run_api_calls_status_check CHECK ((status = ANY (ARRAY['intent'::text, 'succeeded'::text, 'failed'::text, 'outcome_unknown'::text])))
);


--
-- Name: mcp_run_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_run_events (
    event_id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_run_events_kind_check CHECK ((kind ~ '^[a-z_]{1,64}$'::text))
);


--
-- Name: mcp_run_events_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.mcp_run_events ALTER COLUMN event_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.mcp_run_events_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: mcp_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_runs (
    run_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    binding_id uuid,
    binding_revision bigint,
    gateway_license_id uuid NOT NULL,
    credential_profile_id uuid,
    profile_snapshot jsonb NOT NULL,
    owner_tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    tool_version integer NOT NULL,
    authority jsonb NOT NULL,
    inputs jsonb NOT NULL,
    input_hash text NOT NULL,
    idempotency_key text,
    created_by jsonb NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    queue_deadline timestamp with time zone NOT NULL,
    start_deadline timestamp with time zone,
    deadline timestamp with time zone,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    worker_id uuid,
    fence bigint DEFAULT 0 NOT NULL,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    pod_name text,
    pod_uid text,
    cancel_requested boolean DEFAULT false NOT NULL,
    api_calls integer DEFAULT 0 NOT NULL,
    result jsonb,
    error jsonb,
    payload_expired_at timestamp with time zone,
    mode text DEFAULT 'bound'::text NOT NULL,
    runtime text DEFAULT 'kata_python'::text NOT NULL,
    external_ref jsonb,
    status_message text,
    actor jsonb,
    CONSTRAINT mcp_runs_actor_check CHECK (((actor IS NULL) OR (jsonb_typeof(actor) = 'object'::text))),
    CONSTRAINT mcp_runs_api_calls_check CHECK ((api_calls >= 0)),
    CONSTRAINT mcp_runs_binding_revision_check CHECK ((binding_revision > 0)),
    CONSTRAINT mcp_runs_fence_check CHECK ((fence >= 0)),
    CONSTRAINT mcp_runs_idempotency_key_check CHECK ((idempotency_key ~ '^[A-Za-z0-9_.:-]{1,128}$'::text)),
    CONSTRAINT mcp_runs_input_hash_check CHECK ((input_hash ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT mcp_runs_mode_binding CHECK ((((mode = 'bound'::text) AND (binding_id IS NOT NULL) AND (binding_revision IS NOT NULL) AND (credential_profile_id IS NOT NULL)) OR ((mode = 'draft'::text) AND (binding_id IS NULL) AND (binding_revision IS NULL) AND (credential_profile_id IS NULL) AND (owner_tenant_id = tenant_id)))),
    CONSTRAINT mcp_runs_mode_check CHECK ((mode = ANY (ARRAY['bound'::text, 'draft'::text]))),
    CONSTRAINT mcp_runs_run_id_check CHECK ((uuid_extract_version(run_id) = 7)),
    CONSTRAINT mcp_runs_runtime_check CHECK ((runtime = ANY (ARRAY['kata_python'::text, 'n8n_workflow'::text, 'fr_project'::text, 'fr_command'::text]))),
    CONSTRAINT mcp_runs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'starting'::text, 'running'::text, 'cancelling'::text, 'succeeded'::text, 'failed'::text, 'cancelled'::text, 'timed_out'::text, 'interrupted'::text]))),
    CONSTRAINT mcp_runs_status_message_check CHECK ((char_length(status_message) <= 512)),
    CONSTRAINT mcp_runs_worker_id_check CHECK ((uuid_extract_version(worker_id) = 7))
);


--
-- Name: mcp_service_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_service_grants (
    service_id uuid NOT NULL,
    grantee_tenant_id uuid NOT NULL,
    granted_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_service_grants_grantee_tenant_id_check CHECK ((grantee_tenant_id <> public.mcp_platform_tenant()))
);


--
-- Name: mcp_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_services (
    service_id uuid NOT NULL,
    service_key text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    owner_tenant_id uuid DEFAULT public.mcp_platform_tenant() NOT NULL,
    CONSTRAINT mcp_services_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_services_service_id_v7 CHECK ((((get_byte(uuid_send(service_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(service_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_source_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_source_events (
    event_id bigint NOT NULL,
    source_id uuid NOT NULL,
    source_key text NOT NULL,
    revision bigint NOT NULL,
    event text NOT NULL,
    actor jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    owner_tenant_id uuid DEFAULT public.mcp_platform_tenant() NOT NULL,
    CONSTRAINT mcp_source_events_event_check CHECK ((event = ANY (ARRAY['created'::text, 'updated'::text, 'token_set'::text, 'disabled'::text, 'enabled'::text])))
);


--
-- Name: mcp_source_events_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.mcp_source_events ALTER COLUMN event_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.mcp_source_events_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: mcp_source_specs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_source_specs (
    owner_tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    sha256 text NOT NULL,
    fetched_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    bytes integer NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT mcp_source_specs_bytes_check CHECK ((bytes > 0)),
    CONSTRAINT mcp_source_specs_sha256_check CHECK ((sha256 ~ '^[a-f0-9]{64}$'::text))
);


--
-- Name: mcp_task_inputs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_task_inputs (
    input_key text NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    source_ref text NOT NULL,
    request jsonb NOT NULL,
    state text DEFAULT 'open'::text NOT NULL,
    response jsonb,
    actor jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    answered_at timestamp with time zone,
    closed_at timestamp with time zone,
    expires_at timestamp with time zone,
    CONSTRAINT mcp_task_inputs_input_key_check CHECK ((char_length(input_key) <= 200)),
    CONSTRAINT mcp_task_inputs_request_check CHECK ((jsonb_typeof(request) = 'object'::text)),
    CONSTRAINT mcp_task_inputs_response_check CHECK (((response IS NULL) OR (jsonb_typeof(response) = 'object'::text))),
    CONSTRAINT mcp_task_inputs_source_ref_check CHECK ((char_length(source_ref) <= 200)),
    CONSTRAINT mcp_task_inputs_state_check CHECK ((state = ANY (ARRAY['open'::text, 'answered'::text, 'forwarded'::text, 'closed'::text])))
);


--
-- Name: mcp_tenant_execution_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tenant_execution_locks (
    tenant_id uuid NOT NULL,
    last_claimed_at timestamp with time zone DEFAULT '-infinity'::timestamp with time zone NOT NULL
);


--
-- Name: mcp_tool_call_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_call_audit (
    audit_id uuid DEFAULT uuidv7() NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    tool text NOT NULL,
    status text NOT NULL,
    principal_kind text NOT NULL,
    auth_method text NOT NULL,
    principal text NOT NULL,
    tenant_id text,
    latency_ms integer NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT mcp_tool_call_audit_auth_method_check CHECK ((auth_method = ANY (ARRAY['license'::text, 'keycloak'::text]))),
    CONSTRAINT mcp_tool_call_audit_details_check CHECK (((jsonb_typeof(details) = 'object'::text) AND (octet_length((details)::text) <= 16384))),
    CONSTRAINT mcp_tool_call_audit_latency_ms_check CHECK ((latency_ms >= 0)),
    CONSTRAINT mcp_tool_call_audit_principal_check CHECK (((length(principal) >= 1) AND (length(principal) <= 256))),
    CONSTRAINT mcp_tool_call_audit_principal_kind_check CHECK ((principal_kind = ANY (ARRAY['carebus_licence'::text, 'keycloak_service'::text, 'tenant_author'::text]))),
    CONSTRAINT mcp_tool_call_audit_status_check CHECK ((status = ANY (ARRAY['success'::text, 'failure'::text, 'denied'::text]))),
    CONSTRAINT mcp_tool_call_audit_tenant_id_check CHECK (((tenant_id IS NULL) OR ((length(tenant_id) >= 1) AND (length(tenant_id) <= 256)))),
    CONSTRAINT mcp_tool_call_audit_tool_check CHECK (((length(tool) >= 1) AND (length(tool) <= 256)))
);


--
-- Name: mcp_tool_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_shares (
    owner_tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    grantee_tenant_id uuid NOT NULL,
    granted_by jsonb NOT NULL,
    CONSTRAINT mcp_tool_shares_check CHECK ((owner_tenant_id <> grantee_tenant_id)),
    CONSTRAINT mcp_tool_shares_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_tool_version_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_version_files (
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    version integer NOT NULL,
    path text NOT NULL,
    content text NOT NULL,
    CONSTRAINT mcp_tool_version_files_path_check CHECK (((path <> ''::text) AND (path !~ '(^/|\\|:|(^|/)\.{1,2}(/|$)|//|/$)'::text))),
    CONSTRAINT mcp_tool_version_files_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_tool_version_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_version_operations (
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    version integer NOT NULL,
    operation_id uuid NOT NULL,
    operation_version integer NOT NULL,
    CONSTRAINT mcp_tool_version_operations_operation_id_v7 CHECK ((((get_byte(uuid_send(operation_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(operation_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_tool_version_operations_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_tool_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_versions (
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    version integer NOT NULL,
    manifest jsonb NOT NULL,
    package_sha256 text NOT NULL,
    file_count integer NOT NULL,
    operation_count integer NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    source_tool_id uuid,
    source_version integer,
    creation_tx text DEFAULT (pg_current_xact_id())::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_tool_versions_check CHECK (((source_tool_id IS NULL) = (source_version IS NULL))),
    CONSTRAINT mcp_tool_versions_check1 CHECK (((manifest ?& ARRAY['tenant_id'::text, 'tool_id'::text, 'package_sha256'::text, 'allowed_operations'::text]) AND ((manifest ->> 'tenant_id'::text) = (tenant_id)::text) AND ((manifest ->> 'tool_id'::text) = (tool_id)::text) AND (((manifest ->> 'version'::text))::integer = version) AND ((manifest ->> 'package_sha256'::text) = package_sha256))),
    CONSTRAINT mcp_tool_versions_file_count_check CHECK ((file_count > 0)),
    CONSTRAINT mcp_tool_versions_manifest_check CHECK (((jsonb_typeof(manifest) = 'object'::text) AND (manifest ?& ARRAY['schema_version'::text, 'version'::text]) AND ((manifest ->> 'schema_version'::text) = '1'::text))),
    CONSTRAINT mcp_tool_versions_operation CHECK (((jsonb_typeof((manifest -> 'operation'::text)) = 'string'::text) AND ((manifest ->> 'operation'::text) ~ '^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$'::text))),
    CONSTRAINT mcp_tool_versions_operation_count_check CHECK ((operation_count >= 0)),
    CONSTRAINT mcp_tool_versions_package_sha256_check CHECK ((package_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT mcp_tool_versions_source_tool_id_v7 CHECK ((((get_byte(uuid_send(source_tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(source_tool_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_tool_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'disabled'::text, 'retired'::text]))),
    CONSTRAINT mcp_tool_versions_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_tool_versions_version_check CHECK ((version > 0))
);


--
-- Name: mcp_toolkit_inclusions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_toolkit_inclusions (
    tenant_id uuid NOT NULL,
    toolkit_id uuid NOT NULL,
    version integer NOT NULL,
    included_id uuid NOT NULL,
    included_version integer NOT NULL,
    CONSTRAINT mcp_toolkit_inclusions_check CHECK ((toolkit_id <> included_id)),
    CONSTRAINT mcp_toolkit_inclusions_included_id_v7 CHECK ((((get_byte(uuid_send(included_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(included_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_toolkit_inclusions_toolkit_id_v7 CHECK ((((get_byte(uuid_send(toolkit_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(toolkit_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_toolkit_version_tools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_toolkit_version_tools (
    tenant_id uuid NOT NULL,
    toolkit_id uuid NOT NULL,
    version integer NOT NULL,
    owner_tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    tool_version integer NOT NULL,
    public_name text NOT NULL,
    CONSTRAINT mcp_toolkit_version_tools_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_toolkit_version_tools_toolkit_id_v7 CHECK ((((get_byte(uuid_send(toolkit_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(toolkit_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_toolkit_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_toolkit_versions (
    tenant_id uuid NOT NULL,
    toolkit_id uuid NOT NULL,
    version integer NOT NULL,
    manifest jsonb NOT NULL,
    tools jsonb NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_by jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    creation_tx text DEFAULT (pg_current_xact_id())::text NOT NULL,
    CONSTRAINT mcp_toolkit_versions_check CHECK (((manifest ?& ARRAY['schema_version'::text, 'tenant_id'::text, 'toolkit_id'::text, 'version'::text, 'tools'::text, 'includes'::text]) AND ((manifest ->> 'schema_version'::text) = '1'::text) AND ((manifest ->> 'tenant_id'::text) = (tenant_id)::text) AND ((manifest ->> 'toolkit_id'::text) = (toolkit_id)::text) AND (((manifest ->> 'version'::text))::integer = version))),
    CONSTRAINT mcp_toolkit_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'disabled'::text, 'retired'::text]))),
    CONSTRAINT mcp_toolkit_versions_toolkit_id_v7 CHECK ((((get_byte(uuid_send(toolkit_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(toolkit_id), 8) >> 6) = 2))),
    CONSTRAINT mcp_toolkit_versions_tools_check CHECK (((jsonb_typeof(tools) = 'array'::text) AND ((jsonb_array_length(tools) >= 1) AND (jsonb_array_length(tools) <= 128)))),
    CONSTRAINT mcp_toolkit_versions_version_check CHECK ((version > 0))
);


--
-- Name: mcp_toolkits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_toolkits (
    tenant_id uuid NOT NULL,
    toolkit_id uuid NOT NULL,
    name text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_toolkits_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_toolkits_toolkit_id_v7 CHECK ((((get_byte(uuid_send(toolkit_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(toolkit_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_tools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tools (
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    public_name text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    retired boolean DEFAULT false NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mcp_tools_revision_check CHECK ((revision > 0)),
    CONSTRAINT mcp_tools_tool_id_v7 CHECK ((((get_byte(uuid_send(tool_id), 6) >> 4) = 7) AND ((get_byte(uuid_send(tool_id), 8) >> 6) = 2)))
);


--
-- Name: mcp_run_activity seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_activity ALTER COLUMN seq SET DEFAULT nextval('public.mcp_run_activity_seq_seq'::regclass);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: mcp_access_events mcp_access_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_access_events
    ADD CONSTRAINT mcp_access_events_pkey PRIMARY KEY (event_id);


--
-- Name: mcp_api_permits mcp_api_permits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_api_permits
    ADD CONSTRAINT mcp_api_permits_pkey PRIMARY KEY (permit_id);


--
-- Name: mcp_api_rate_windows mcp_api_rate_windows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_api_rate_windows
    ADD CONSTRAINT mcp_api_rate_windows_pkey PRIMARY KEY (tenant_id, service_id, window_start);


--
-- Name: mcp_binding_ensures mcp_binding_ensures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_ensures
    ADD CONSTRAINT mcp_binding_ensures_pkey PRIMARY KEY (ensure_id);


--
-- Name: mcp_binding_ensures mcp_binding_ensures_tenant_id_product_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_ensures
    ADD CONSTRAINT mcp_binding_ensures_tenant_id_product_key UNIQUE (tenant_id, product);


--
-- Name: mcp_binding_toolkits mcp_binding_toolkits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_toolkits
    ADD CONSTRAINT mcp_binding_toolkits_pkey PRIMARY KEY (tenant_id, binding_id, owner_tenant_id, toolkit_id, version);


--
-- Name: mcp_binding_tools mcp_binding_tools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_tools
    ADD CONSTRAINT mcp_binding_tools_pkey PRIMARY KEY (tenant_id, binding_id, public_name);


--
-- Name: mcp_bindings mcp_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_bindings
    ADD CONSTRAINT mcp_bindings_pkey PRIMARY KEY (tenant_id, binding_id);


--
-- Name: mcp_bindings mcp_bindings_token_sha256_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_bindings
    ADD CONSTRAINT mcp_bindings_token_sha256_key UNIQUE (token_sha256);


--
-- Name: mcp_catalog_state mcp_catalog_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_catalog_state
    ADD CONSTRAINT mcp_catalog_state_pkey PRIMARY KEY (singleton);


--
-- Name: mcp_credential_profiles mcp_credential_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credential_profiles
    ADD CONSTRAINT mcp_credential_profiles_pkey PRIMARY KEY (tenant_id, profile_id);


--
-- Name: mcp_credential_profiles mcp_credential_profiles_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credential_profiles
    ADD CONSTRAINT mcp_credential_profiles_tenant_id_name_key UNIQUE (tenant_id, name);


--
-- Name: mcp_credential_refs mcp_credential_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credential_refs
    ADD CONSTRAINT mcp_credential_refs_pkey PRIMARY KEY (tenant_id, profile_id, service_key);


--
-- Name: mcp_execution_slots mcp_execution_slots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_execution_slots
    ADD CONSTRAINT mcp_execution_slots_pkey PRIMARY KEY (slot_id);


--
-- Name: mcp_execution_slots mcp_execution_slots_run_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_execution_slots
    ADD CONSTRAINT mcp_execution_slots_run_id_key UNIQUE (run_id);


--
-- Name: mcp_operation_keys mcp_operation_keys_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_operation_keys
    ADD CONSTRAINT mcp_operation_keys_operation_id_key UNIQUE (operation_id);


--
-- Name: mcp_operation_keys mcp_operation_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_operation_keys
    ADD CONSTRAINT mcp_operation_keys_pkey PRIMARY KEY (service_id, op_key);


--
-- Name: mcp_operation_versions mcp_operation_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_operation_versions
    ADD CONSTRAINT mcp_operation_versions_pkey PRIMARY KEY (operation_id, version);


--
-- Name: mcp_protocol_sessions mcp_protocol_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_protocol_sessions
    ADD CONSTRAINT mcp_protocol_sessions_pkey PRIMARY KEY (session_sha256);


--
-- Name: mcp_run_activity mcp_run_activity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_activity
    ADD CONSTRAINT mcp_run_activity_pkey PRIMARY KEY (run_id, seq);


--
-- Name: mcp_run_api_calls mcp_run_api_calls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_api_calls
    ADD CONSTRAINT mcp_run_api_calls_pkey PRIMARY KEY (tenant_id, run_id, sequence);


--
-- Name: mcp_run_events mcp_run_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_events
    ADD CONSTRAINT mcp_run_events_pkey PRIMARY KEY (event_id);


--
-- Name: mcp_runs mcp_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_pkey PRIMARY KEY (run_id);


--
-- Name: mcp_runs mcp_runs_tenant_id_binding_id_owner_tenant_id_tool_id_tool__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_tenant_id_binding_id_owner_tenant_id_tool_id_tool__key UNIQUE (tenant_id, binding_id, owner_tenant_id, tool_id, tool_version, idempotency_key);


--
-- Name: mcp_runs mcp_runs_tenant_id_run_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_tenant_id_run_id_key UNIQUE (tenant_id, run_id);


--
-- Name: mcp_service_grants mcp_service_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_service_grants
    ADD CONSTRAINT mcp_service_grants_pkey PRIMARY KEY (service_id, grantee_tenant_id);


--
-- Name: mcp_service_versions mcp_service_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_service_versions
    ADD CONSTRAINT mcp_service_versions_pkey PRIMARY KEY (service_id, version);


--
-- Name: mcp_services mcp_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_services
    ADD CONSTRAINT mcp_services_pkey PRIMARY KEY (service_id);


--
-- Name: mcp_services mcp_services_service_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_services
    ADD CONSTRAINT mcp_services_service_key_key UNIQUE (service_key);


--
-- Name: mcp_source_events mcp_source_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_source_events
    ADD CONSTRAINT mcp_source_events_pkey PRIMARY KEY (event_id);


--
-- Name: mcp_source_specs mcp_source_specs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_source_specs
    ADD CONSTRAINT mcp_source_specs_pkey PRIMARY KEY (source_id, sha256);


--
-- Name: mcp_sources mcp_sources_owner_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_sources
    ADD CONSTRAINT mcp_sources_owner_id_key UNIQUE (source_id, owner_tenant_id);


--
-- Name: mcp_sources mcp_sources_owner_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_sources
    ADD CONSTRAINT mcp_sources_owner_key UNIQUE (owner_tenant_id, source_key);


--
-- Name: mcp_sources mcp_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_sources
    ADD CONSTRAINT mcp_sources_pkey PRIMARY KEY (source_id);


--
-- Name: mcp_task_inputs mcp_task_inputs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_task_inputs
    ADD CONSTRAINT mcp_task_inputs_pkey PRIMARY KEY (input_key);


--
-- Name: mcp_task_inputs mcp_task_inputs_run_id_source_ref_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_task_inputs
    ADD CONSTRAINT mcp_task_inputs_run_id_source_ref_key UNIQUE (run_id, source_ref);


--
-- Name: mcp_tenant_execution_locks mcp_tenant_execution_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tenant_execution_locks
    ADD CONSTRAINT mcp_tenant_execution_locks_pkey PRIMARY KEY (tenant_id);


--
-- Name: mcp_tool_call_audit mcp_tool_call_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_call_audit
    ADD CONSTRAINT mcp_tool_call_audit_pkey PRIMARY KEY (audit_id);


--
-- Name: mcp_tool_shares mcp_tool_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_shares
    ADD CONSTRAINT mcp_tool_shares_pkey PRIMARY KEY (owner_tenant_id, tool_id, grantee_tenant_id);


--
-- Name: mcp_tool_version_files mcp_tool_version_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_version_files
    ADD CONSTRAINT mcp_tool_version_files_pkey PRIMARY KEY (tenant_id, tool_id, version, path);


--
-- Name: mcp_tool_version_operations mcp_tool_version_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_version_operations
    ADD CONSTRAINT mcp_tool_version_operations_pkey PRIMARY KEY (tenant_id, tool_id, version, operation_id, operation_version);


--
-- Name: mcp_tool_versions mcp_tool_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_versions
    ADD CONSTRAINT mcp_tool_versions_pkey PRIMARY KEY (tenant_id, tool_id, version);


--
-- Name: mcp_toolkit_inclusions mcp_toolkit_inclusions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_inclusions
    ADD CONSTRAINT mcp_toolkit_inclusions_pkey PRIMARY KEY (tenant_id, toolkit_id, version, included_id, included_version);


--
-- Name: mcp_toolkit_version_tools mcp_toolkit_version_tools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_version_tools
    ADD CONSTRAINT mcp_toolkit_version_tools_pkey PRIMARY KEY (tenant_id, toolkit_id, version, public_name);


--
-- Name: mcp_toolkit_versions mcp_toolkit_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_versions
    ADD CONSTRAINT mcp_toolkit_versions_pkey PRIMARY KEY (tenant_id, toolkit_id, version);


--
-- Name: mcp_toolkits mcp_toolkits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkits
    ADD CONSTRAINT mcp_toolkits_pkey PRIMARY KEY (tenant_id, toolkit_id);


--
-- Name: mcp_toolkits mcp_toolkits_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkits
    ADD CONSTRAINT mcp_toolkits_tenant_id_name_key UNIQUE (tenant_id, name);


--
-- Name: mcp_tools mcp_tools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_pkey PRIMARY KEY (tenant_id, tool_id);


--
-- Name: mcp_tools mcp_tools_tenant_id_public_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_tenant_id_public_name_key UNIQUE (tenant_id, public_name);


--
-- Name: mcp_access_events_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_access_events_tenant_idx ON public.mcp_access_events USING btree (tenant_id, event_id);


--
-- Name: mcp_api_calls_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_api_calls_recent ON public.mcp_run_api_calls USING btree (started_at DESC);


--
-- Name: mcp_api_permits_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_api_permits_expiry ON public.mcp_api_permits USING btree (expires_at);


--
-- Name: mcp_api_permits_service; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_api_permits_service ON public.mcp_api_permits USING btree (service_id, expires_at);


--
-- Name: mcp_api_rate_windows_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_api_rate_windows_expiry ON public.mcp_api_rate_windows USING btree (window_start);


--
-- Name: mcp_binding_toolkits_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_binding_toolkits_owner_idx ON public.mcp_binding_toolkits USING btree (owner_tenant_id, toolkit_id, version);


--
-- Name: mcp_bindings_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_bindings_expiry_idx ON public.mcp_bindings USING btree (tenant_id, expires_at) WHERE (enabled AND (NOT revoked));


--
-- Name: mcp_operations_service_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_operations_service_idx ON public.mcp_operation_versions USING btree (service_id, service_version);


--
-- Name: mcp_run_activity_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_run_activity_run ON public.mcp_run_activity USING btree (run_id);


--
-- Name: mcp_run_events_page; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_run_events_page ON public.mcp_run_events USING btree (tenant_id, run_id, event_id);


--
-- Name: mcp_runs_draft_idempotency; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mcp_runs_draft_idempotency ON public.mcp_runs USING btree (tenant_id, tool_id, tool_version, idempotency_key) WHERE ((mode = 'draft'::text) AND (idempotency_key IS NOT NULL));


--
-- Name: mcp_runs_leases; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_runs_leases ON public.mcp_runs USING btree (lease_until) WHERE (worker_id IS NOT NULL);


--
-- Name: mcp_runs_queue; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_runs_queue ON public.mcp_runs USING btree (created_at) WHERE (status = 'queued'::text);


--
-- Name: mcp_runs_retention; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_runs_retention ON public.mcp_runs USING btree (finished_at) WHERE ((payload_expired_at IS NULL) AND (finished_at IS NOT NULL));


--
-- Name: mcp_runs_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_runs_tenant ON public.mcp_runs USING btree (tenant_id, binding_id, created_at);


--
-- Name: mcp_service_grants_grantee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_service_grants_grantee_idx ON public.mcp_service_grants USING btree (grantee_tenant_id);


--
-- Name: mcp_services_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_services_owner_idx ON public.mcp_services USING btree (owner_tenant_id);


--
-- Name: mcp_sessions_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_sessions_expiry_idx ON public.mcp_protocol_sessions USING btree (expires_at);


--
-- Name: mcp_source_events_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_source_events_source_idx ON public.mcp_source_events USING btree (source_id, event_id);


--
-- Name: mcp_source_specs_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_source_specs_owner_idx ON public.mcp_source_specs USING btree (owner_tenant_id, source_id, fetched_at);


--
-- Name: mcp_sources_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_sources_owner_idx ON public.mcp_sources USING btree (owner_tenant_id, status);


--
-- Name: mcp_task_inputs_forward; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_task_inputs_forward ON public.mcp_task_inputs USING btree (answered_at) WHERE (state = 'answered'::text);


--
-- Name: mcp_task_inputs_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_task_inputs_open ON public.mcp_task_inputs USING btree (run_id) WHERE (state = 'open'::text);


--
-- Name: mcp_tool_call_audit_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_tool_call_audit_created_idx ON public.mcp_tool_call_audit USING btree (created_at);


--
-- Name: mcp_tool_call_audit_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_tool_call_audit_tenant_idx ON public.mcp_tool_call_audit USING btree (tenant_id, created_at) WHERE (tenant_id IS NOT NULL);


--
-- Name: mcp_tool_operations_reverse_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_tool_operations_reverse_idx ON public.mcp_tool_version_operations USING btree (operation_id, operation_version);


--
-- Name: mcp_tool_versions_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_tool_versions_status_idx ON public.mcp_tool_versions USING btree (tenant_id, status);


--
-- Name: mcp_toolkit_members_reverse_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_toolkit_members_reverse_idx ON public.mcp_toolkit_version_tools USING btree (owner_tenant_id, tool_id, tool_version);


--
-- Name: mcp_tools_tenant_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_tools_tenant_name_idx ON public.mcp_tools USING btree (tenant_id, public_name);


--
-- Name: mcp_access_events access_event_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER access_event_guard BEFORE DELETE OR UPDATE ON public.mcp_access_events FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_access_event();


--
-- Name: mcp_bindings binding_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER binding_complete AFTER INSERT OR UPDATE ON public.mcp_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_access_complete('binding');


--
-- Name: mcp_binding_ensures binding_ensure_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER binding_ensure_guard BEFORE DELETE OR UPDATE ON public.mcp_binding_ensures FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_binding_ensure();


--
-- Name: mcp_bindings binding_generation; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER binding_generation AFTER INSERT OR UPDATE ON public.mcp_bindings FOR EACH ROW EXECUTE FUNCTION public.mcp_access_generation();


--
-- Name: mcp_binding_toolkits binding_toolkits_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER binding_toolkits_complete AFTER INSERT OR DELETE OR UPDATE ON public.mcp_binding_toolkits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_access_complete('binding');


--
-- Name: mcp_binding_tools binding_tools_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER binding_tools_complete AFTER INSERT OR DELETE OR UPDATE ON public.mcp_binding_tools DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_access_complete('binding');


--
-- Name: mcp_bindings binding_update_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER binding_update_guard BEFORE DELETE OR UPDATE ON public.mcp_bindings FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_access_update();


--
-- Name: mcp_tool_versions complete_tool_snapshot; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER complete_tool_snapshot AFTER INSERT ON public.mcp_tool_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_check_package_complete();


--
-- Name: mcp_tool_version_files file_content_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER file_content_guard BEFORE INSERT OR DELETE OR UPDATE ON public.mcp_tool_version_files FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_children();


--
-- Name: mcp_service_grants grant_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER grant_visibility AFTER INSERT OR DELETE OR UPDATE ON public.mcp_service_grants FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_run_api_calls mcp_api_call_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mcp_api_call_guard BEFORE DELETE OR UPDATE ON public.mcp_run_api_calls FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_execution_journal();


--
-- Name: mcp_run_events mcp_run_event_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mcp_run_event_guard BEFORE DELETE OR UPDATE ON public.mcp_run_events FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_execution_journal();


--
-- Name: mcp_runs mcp_runs_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mcp_runs_guard BEFORE DELETE OR UPDATE ON public.mcp_runs FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_run();


--
-- Name: mcp_operation_keys operation_key_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_key_guard BEFORE INSERT OR DELETE OR UPDATE ON public.mcp_operation_keys FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_operation_key();


--
-- Name: mcp_operation_versions operation_publication; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_publication BEFORE INSERT OR UPDATE ON public.mcp_operation_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_check_publication();


--
-- Name: mcp_tool_version_operations operation_reference_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_reference_guard BEFORE INSERT OR DELETE OR UPDATE ON public.mcp_tool_version_operations FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_children();


--
-- Name: mcp_operation_versions operation_snapshot_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_snapshot_guard BEFORE DELETE OR UPDATE ON public.mcp_operation_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_snapshot();


--
-- Name: mcp_tool_version_operations operation_tenancy_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_tenancy_guard BEFORE INSERT ON public.mcp_tool_version_operations FOR EACH ROW EXECUTE FUNCTION public.mcp_check_operation_reference();


--
-- Name: mcp_operation_versions operation_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER operation_visibility AFTER UPDATE ON public.mcp_operation_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_credential_profiles profile_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER profile_complete AFTER INSERT OR UPDATE ON public.mcp_credential_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_access_complete('profile');


--
-- Name: mcp_credential_profiles profile_generation; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER profile_generation AFTER INSERT OR UPDATE ON public.mcp_credential_profiles FOR EACH ROW EXECUTE FUNCTION public.mcp_access_generation();


--
-- Name: mcp_credential_refs profile_refs_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER profile_refs_complete AFTER INSERT OR DELETE OR UPDATE ON public.mcp_credential_refs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_access_complete('profile');


--
-- Name: mcp_credential_profiles profile_update_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER profile_update_guard BEFORE DELETE OR UPDATE ON public.mcp_credential_profiles FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_access_update();


--
-- Name: mcp_service_grants service_grant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_grant_guard BEFORE INSERT OR UPDATE ON public.mcp_service_grants FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_service_grant();


--
-- Name: mcp_services service_identity_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_identity_guard BEFORE DELETE OR UPDATE ON public.mcp_services FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_identity();


--
-- Name: mcp_service_versions service_publication; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_publication BEFORE INSERT OR UPDATE ON public.mcp_service_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_check_publication();


--
-- Name: mcp_service_versions service_snapshot_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_snapshot_guard BEFORE DELETE OR UPDATE ON public.mcp_service_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_snapshot();


--
-- Name: mcp_service_versions service_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_visibility AFTER UPDATE ON public.mcp_service_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_tool_shares share_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER share_visibility AFTER INSERT OR DELETE OR UPDATE ON public.mcp_tool_shares FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_sources source_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER source_guard BEFORE DELETE OR UPDATE ON public.mcp_sources FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_source();


--
-- Name: mcp_tool_call_audit tool_call_audit_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_call_audit_guard BEFORE DELETE OR UPDATE ON public.mcp_tool_call_audit FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_tool_call_audit();


--
-- Name: mcp_tools tool_identity_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_identity_guard BEFORE DELETE OR UPDATE ON public.mcp_tools FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_identity();


--
-- Name: mcp_tool_versions tool_publication; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_publication BEFORE INSERT OR UPDATE ON public.mcp_tool_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_check_publication();


--
-- Name: mcp_tools tool_retirement; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_retirement AFTER UPDATE ON public.mcp_tools FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_tool_versions tool_snapshot_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_snapshot_guard BEFORE DELETE OR UPDATE ON public.mcp_tool_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_snapshot();


--
-- Name: mcp_tool_versions tool_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tool_visibility AFTER UPDATE ON public.mcp_tool_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_toolkit_versions toolkit_complete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER toolkit_complete AFTER INSERT ON public.mcp_toolkit_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mcp_toolkit_complete();


--
-- Name: mcp_toolkits toolkit_identity_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_identity_guard BEFORE DELETE OR UPDATE ON public.mcp_toolkits FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_identity();


--
-- Name: mcp_toolkit_inclusions toolkit_inclusion_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_inclusion_guard BEFORE INSERT OR DELETE OR UPDATE ON public.mcp_toolkit_inclusions FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_toolkit_child();


--
-- Name: mcp_toolkit_versions toolkit_publication; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_publication BEFORE INSERT OR UPDATE ON public.mcp_toolkit_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_toolkit_publication();


--
-- Name: mcp_toolkit_versions toolkit_snapshot_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_snapshot_guard BEFORE DELETE OR UPDATE ON public.mcp_toolkit_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_snapshot();


--
-- Name: mcp_toolkit_version_tools toolkit_tool_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_tool_guard BEFORE INSERT OR DELETE OR UPDATE ON public.mcp_toolkit_version_tools FOR EACH ROW EXECUTE FUNCTION public.mcp_guard_toolkit_child();


--
-- Name: mcp_toolkit_versions toolkit_visibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER toolkit_visibility AFTER UPDATE ON public.mcp_toolkit_versions FOR EACH ROW EXECUTE FUNCTION public.mcp_bump_generation();


--
-- Name: mcp_api_permits mcp_api_permits_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_api_permits
    ADD CONSTRAINT mcp_api_permits_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.mcp_services(service_id);


--
-- Name: mcp_api_permits mcp_api_permits_tenant_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_api_permits
    ADD CONSTRAINT mcp_api_permits_tenant_id_run_id_fkey FOREIGN KEY (tenant_id, run_id) REFERENCES public.mcp_runs(tenant_id, run_id);


--
-- Name: mcp_api_rate_windows mcp_api_rate_windows_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_api_rate_windows
    ADD CONSTRAINT mcp_api_rate_windows_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.mcp_services(service_id);


--
-- Name: mcp_binding_ensures mcp_binding_ensures_tenant_id_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_ensures
    ADD CONSTRAINT mcp_binding_ensures_tenant_id_binding_id_fkey FOREIGN KEY (tenant_id, binding_id) REFERENCES public.mcp_bindings(tenant_id, binding_id);


--
-- Name: mcp_binding_ensures mcp_binding_ensures_tenant_id_credential_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_ensures
    ADD CONSTRAINT mcp_binding_ensures_tenant_id_credential_profile_id_fkey FOREIGN KEY (tenant_id, credential_profile_id) REFERENCES public.mcp_credential_profiles(tenant_id, profile_id);


--
-- Name: mcp_binding_toolkits mcp_binding_toolkits_owner_tenant_id_toolkit_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_toolkits
    ADD CONSTRAINT mcp_binding_toolkits_owner_tenant_id_toolkit_id_version_fkey FOREIGN KEY (owner_tenant_id, toolkit_id, version) REFERENCES public.mcp_toolkit_versions(tenant_id, toolkit_id, version);


--
-- Name: mcp_binding_toolkits mcp_binding_toolkits_tenant_id_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_toolkits
    ADD CONSTRAINT mcp_binding_toolkits_tenant_id_binding_id_fkey FOREIGN KEY (tenant_id, binding_id) REFERENCES public.mcp_bindings(tenant_id, binding_id);


--
-- Name: mcp_binding_tools mcp_binding_tools_owner_tenant_id_tool_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_tools
    ADD CONSTRAINT mcp_binding_tools_owner_tenant_id_tool_id_version_fkey FOREIGN KEY (owner_tenant_id, tool_id, version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_binding_tools mcp_binding_tools_tenant_id_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_binding_tools
    ADD CONSTRAINT mcp_binding_tools_tenant_id_binding_id_fkey FOREIGN KEY (tenant_id, binding_id) REFERENCES public.mcp_bindings(tenant_id, binding_id);


--
-- Name: mcp_bindings mcp_bindings_tenant_id_credential_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_bindings
    ADD CONSTRAINT mcp_bindings_tenant_id_credential_profile_id_fkey FOREIGN KEY (tenant_id, credential_profile_id) REFERENCES public.mcp_credential_profiles(tenant_id, profile_id);


--
-- Name: mcp_credential_refs mcp_credential_refs_tenant_id_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credential_refs
    ADD CONSTRAINT mcp_credential_refs_tenant_id_profile_id_fkey FOREIGN KEY (tenant_id, profile_id) REFERENCES public.mcp_credential_profiles(tenant_id, profile_id);


--
-- Name: mcp_execution_slots mcp_execution_slots_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_execution_slots
    ADD CONSTRAINT mcp_execution_slots_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.mcp_runs(run_id);


--
-- Name: mcp_operation_keys mcp_operation_keys_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_operation_keys
    ADD CONSTRAINT mcp_operation_keys_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.mcp_services(service_id);


--
-- Name: mcp_operation_versions mcp_operation_versions_service_id_service_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_operation_versions
    ADD CONSTRAINT mcp_operation_versions_service_id_service_version_fkey FOREIGN KEY (service_id, service_version) REFERENCES public.mcp_service_versions(service_id, version);


--
-- Name: mcp_protocol_sessions mcp_protocol_sessions_tenant_id_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_protocol_sessions
    ADD CONSTRAINT mcp_protocol_sessions_tenant_id_binding_id_fkey FOREIGN KEY (tenant_id, binding_id) REFERENCES public.mcp_bindings(tenant_id, binding_id);


--
-- Name: mcp_run_activity mcp_run_activity_tenant_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_activity
    ADD CONSTRAINT mcp_run_activity_tenant_id_run_id_fkey FOREIGN KEY (tenant_id, run_id) REFERENCES public.mcp_runs(tenant_id, run_id);


--
-- Name: mcp_run_api_calls mcp_run_api_calls_operation_id_operation_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_api_calls
    ADD CONSTRAINT mcp_run_api_calls_operation_id_operation_version_fkey FOREIGN KEY (operation_id, operation_version) REFERENCES public.mcp_operation_versions(operation_id, version);


--
-- Name: mcp_run_api_calls mcp_run_api_calls_tenant_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_api_calls
    ADD CONSTRAINT mcp_run_api_calls_tenant_id_run_id_fkey FOREIGN KEY (tenant_id, run_id) REFERENCES public.mcp_runs(tenant_id, run_id);


--
-- Name: mcp_run_events mcp_run_events_tenant_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_run_events
    ADD CONSTRAINT mcp_run_events_tenant_id_run_id_fkey FOREIGN KEY (tenant_id, run_id) REFERENCES public.mcp_runs(tenant_id, run_id);


--
-- Name: mcp_runs mcp_runs_owner_tenant_id_tool_id_tool_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_owner_tenant_id_tool_id_tool_version_fkey FOREIGN KEY (owner_tenant_id, tool_id, tool_version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_runs mcp_runs_tenant_id_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_tenant_id_binding_id_fkey FOREIGN KEY (tenant_id, binding_id) REFERENCES public.mcp_bindings(tenant_id, binding_id);


--
-- Name: mcp_runs mcp_runs_tenant_id_credential_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_runs
    ADD CONSTRAINT mcp_runs_tenant_id_credential_profile_id_fkey FOREIGN KEY (tenant_id, credential_profile_id) REFERENCES public.mcp_credential_profiles(tenant_id, profile_id);


--
-- Name: mcp_service_grants mcp_service_grants_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_service_grants
    ADD CONSTRAINT mcp_service_grants_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.mcp_services(service_id);


--
-- Name: mcp_service_versions mcp_service_versions_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_service_versions
    ADD CONSTRAINT mcp_service_versions_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.mcp_services(service_id);


--
-- Name: mcp_source_events mcp_source_events_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_source_events
    ADD CONSTRAINT mcp_source_events_owner_fkey FOREIGN KEY (source_id, owner_tenant_id) REFERENCES public.mcp_sources(source_id, owner_tenant_id);


--
-- Name: mcp_source_events mcp_source_events_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_source_events
    ADD CONSTRAINT mcp_source_events_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.mcp_sources(source_id);


--
-- Name: mcp_source_specs mcp_source_specs_source_id_owner_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_source_specs
    ADD CONSTRAINT mcp_source_specs_source_id_owner_tenant_id_fkey FOREIGN KEY (source_id, owner_tenant_id) REFERENCES public.mcp_sources(source_id, owner_tenant_id);


--
-- Name: mcp_task_inputs mcp_task_inputs_tenant_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_task_inputs
    ADD CONSTRAINT mcp_task_inputs_tenant_id_run_id_fkey FOREIGN KEY (tenant_id, run_id) REFERENCES public.mcp_runs(tenant_id, run_id);


--
-- Name: mcp_tool_shares mcp_tool_shares_owner_tenant_id_tool_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_shares
    ADD CONSTRAINT mcp_tool_shares_owner_tenant_id_tool_id_fkey FOREIGN KEY (owner_tenant_id, tool_id) REFERENCES public.mcp_tools(tenant_id, tool_id);


--
-- Name: mcp_tool_version_files mcp_tool_version_files_tenant_id_tool_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_version_files
    ADD CONSTRAINT mcp_tool_version_files_tenant_id_tool_id_version_fkey FOREIGN KEY (tenant_id, tool_id, version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_tool_version_operations mcp_tool_version_operations_operation_id_operation_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_version_operations
    ADD CONSTRAINT mcp_tool_version_operations_operation_id_operation_version_fkey FOREIGN KEY (operation_id, operation_version) REFERENCES public.mcp_operation_versions(operation_id, version);


--
-- Name: mcp_tool_version_operations mcp_tool_version_operations_tenant_id_tool_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_version_operations
    ADD CONSTRAINT mcp_tool_version_operations_tenant_id_tool_id_version_fkey FOREIGN KEY (tenant_id, tool_id, version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_tool_versions mcp_tool_versions_tenant_id_source_tool_id_source_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_versions
    ADD CONSTRAINT mcp_tool_versions_tenant_id_source_tool_id_source_version_fkey FOREIGN KEY (tenant_id, source_tool_id, source_version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_tool_versions mcp_tool_versions_tenant_id_tool_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_versions
    ADD CONSTRAINT mcp_tool_versions_tenant_id_tool_id_fkey FOREIGN KEY (tenant_id, tool_id) REFERENCES public.mcp_tools(tenant_id, tool_id);


--
-- Name: mcp_toolkit_inclusions mcp_toolkit_inclusions_tenant_id_included_id_included_vers_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_inclusions
    ADD CONSTRAINT mcp_toolkit_inclusions_tenant_id_included_id_included_vers_fkey FOREIGN KEY (tenant_id, included_id, included_version) REFERENCES public.mcp_toolkit_versions(tenant_id, toolkit_id, version);


--
-- Name: mcp_toolkit_inclusions mcp_toolkit_inclusions_tenant_id_toolkit_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_inclusions
    ADD CONSTRAINT mcp_toolkit_inclusions_tenant_id_toolkit_id_version_fkey FOREIGN KEY (tenant_id, toolkit_id, version) REFERENCES public.mcp_toolkit_versions(tenant_id, toolkit_id, version);


--
-- Name: mcp_toolkit_version_tools mcp_toolkit_version_tools_owner_tenant_id_tool_id_tool_ver_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_version_tools
    ADD CONSTRAINT mcp_toolkit_version_tools_owner_tenant_id_tool_id_tool_ver_fkey FOREIGN KEY (owner_tenant_id, tool_id, tool_version) REFERENCES public.mcp_tool_versions(tenant_id, tool_id, version);


--
-- Name: mcp_toolkit_version_tools mcp_toolkit_version_tools_tenant_id_toolkit_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_version_tools
    ADD CONSTRAINT mcp_toolkit_version_tools_tenant_id_toolkit_id_version_fkey FOREIGN KEY (tenant_id, toolkit_id, version) REFERENCES public.mcp_toolkit_versions(tenant_id, toolkit_id, version);


--
-- Name: mcp_toolkit_versions mcp_toolkit_versions_tenant_id_toolkit_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_toolkit_versions
    ADD CONSTRAINT mcp_toolkit_versions_tenant_id_toolkit_id_fkey FOREIGN KEY (tenant_id, toolkit_id) REFERENCES public.mcp_toolkits(tenant_id, toolkit_id);


--
-- PostgreSQL database dump complete
--


