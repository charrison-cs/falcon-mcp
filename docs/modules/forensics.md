<!-- meta:title Falcon Forensics -->
<!-- meta:description Interacting with the Falcon Forensics API endpoints -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Interacting with the Falcon Forensics API endpoints

## API Scopes

- `Forensics:read`
- `Forensics:write`

## Tools

### `falcon_search_collections`

**Required scopes:** `Forensics:read`

Search for Falcon Forensics Collections in your CrowdStrike environment.

Use this to find a collection to inspect, filtering on platform, state,
ffcid, aid, priority, collection tag, config_id or session_id. Consult
falcon://forensics/collections/fql-guide before constructing filter
expressions.

### `falcon_search_collectors`

**Required scopes:** `Forensics:read`

Search for Falcon Forensics Collections in your CrowdStrike environment.

Use this to find a collection to inspect, filtering on platform, state
ffcid, aid, priority, collection tag, config_id or session_id. Consult
falcon://forensics/collectors/fql-guide before constructing filter
expressions

### `falcon_search_configurations_and_templates`

**Required scopes:** `Forensics:read`

Search for Falcon Forensics Configurations in your CrowdStrike environment.

Use this to find a configuration to inspect, filtering on platform, name or description.
Consult falcon://forensics/configurations/fql-guide before constructing filter expressions

### `falcon_validate_configuration`

**Required scopes:** `Forensics:write`

Validate a Forensics configuration without saving it.

Checks the collector objects in `collections` — that each `collector` is
known, valid for the platform, and that its `options` keys and values are
accepted. This validation is also run server-side when using `create_configuration`.

Call this after modifying a cloned template and before
`create_configuration` or `update_configuration`. Does not create or
change anything.

Returns `{"valid": true, ...}` or `{"valid": false, "errors": [...]}`
where each error identifies the offending collector or field. A
`valid: false` result is a successful check, not a tool failure — read
the errors and fix the collections.

### `falcon_create_configuration`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Forensics:write`

Create a new Falcon Forensics collection configuration.

A configuration defines WHAT a forensics collector gathers from a host.
Build `collections` by cloning an existing template from
`search_configurations_and_templates` rather than composing it from
scratch. `validate_configuration` can be called before creating if the
collections array was modified. However, the same validation is done server-side 
when creating the configuration.

Creates a new configuration only; it cannot modify an existing one.

Validation runs server-side on create; nothing is persisted if it fails, and the
rejection includes the specific collector errors. If you need several attempts to
get `collections` right, iterate with `validate_configuration` first — it is
read-only and avoids repeated write calls.

### `falcon_update_configuration`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Forensics:read`, `Forensics:write`

Modify an existing Falcon Forensics configuration.

Supply only the fields you want to change; current values are preserved
for any field you omit. The underlying API is a full-document overwrite,
so this tool reads the configuration first and merges your changes — which
means a concurrent edit by someone else between the read and the write can
be lost.

`collections` is replaced wholesale, not merged. Read the existing array,
modify it, and submit the complete result.

Changing `name` to one already used by another configuration fails with a
duplicate-name conflict and changes nothing.

### `falcon_create_collection`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Forensics:write`

Schedule a Falcon Forensics collection run against a set of hosts.

A collection is an EXECUTION of a configuration: the configuration defines
*what* is gathered, this call defines *which hosts* gather it and *when*.

Typical flow:
  1. `search_configurations_and_templates` (or `create_configuration`) to
     get a `config_id`.
  2. Resolve target host AIDs with host/device search tools.
  3. Call this method with that `config_id` and those AIDs.

Omit `config_id` to use the platform's default configuration, in which case
`platform` is required. Host platforms are validated against the
configuration's platform: mismatched hosts are reported in `errors` while
valid hosts still run (partial success), so always inspect `errors` even on
a successful response.

Creates a new collection run only; it cannot modify an existing one.

### `falcon_cancel_collections`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Forensics:write`

Cancel in-progress Falcon Forensics collection runs.

This stops scheduled and running collections on live endpoints, so data
those hosts had not yet uploaded is not collected. Resolve the exact
collection IDs with `search_collections` first and confirm they are the
intended runs before calling.

Only collections in an active state are cancelled — ones already
complete, failed, or already cancelling are left untouched. Cancelling a
collection does not shut down or remove the collector on the host; use
`shutdown_collectors` for that.

Returns the collections that were actually cancelled. Compare that list
against the IDs you requested: IDs that were already in a terminal state
are reported in `not_cancelled` (partial success), so always inspect the
response rather than assuming every requested run stopped.

### `falcon_deploy_collectors`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Forensics:write`

Deploy the Falcon Forensics collector to specific hosts.

This deploys and executes the collector on live endpoints — a real action on
production machines, not a configuration change. Confirm the AID list is
correct and intended before calling.

Proxy settings are all-or-nothing: supply both proxy_host and proxy_port,
or set no_proxy=true, or omit all three for default behaviour.

Returns the collectors that were actually deployed. Compare that list
against the AIDs you requested — hosts can be silently omitted if they are
already have an active collector session, are already in a deploying state or
are unknown aids.

### `falcon_shutdown_collectors`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Forensics:write`

Shut down running Falcon Forensics collectors on hosts.

This stops live collectors on production endpoints and ends any collection
in progress if force is set to True. Always target specific hosts with `aids` or `ffcids`, which
you should obtain from `search_collectors` — never guess them.

`self_destruct` additionally deletes the collector binary. `force` can abandon
an in-progress collection. Both default to false; leave them there unless specifically required.

Returns the collectors that were shut down. A 'no collectors in progress'
result means there was nothing running to stop and no state changed.

## Resources

- **`falcon://forensics/collections/fql-guide`**: Contains the guide for the `filter` param of the `search_collections` tool.
- **`falcon://forensics/collectors/fql-guide`**: Contains the guide for the `filter` param of the `search_collectors` tool.
- **`falcon://forensics/configurations/fql-guide`**: Contains the guide for the `filter` param of the `search_collectors` tool.
- **`falcon://forensics/configurations/model-guide`**: Contains the guide for the create configuration body of the `create_configuration` tool.
