"""
Forensics module for Falcon MCP Server

This module provides tools for interacting with the Falcon Forensics API endpoints. Creating configurations and dispatching collections to endpoints
"""
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.forensics import (
    CONFIGURATIONS_MODEL_GUIDE,
    SEARCH_COLLECTIONS_FQL_DOCUMENTATION,
    SEARCH_COLLECTORS_FQL_DOCUMENTATION,
    SEARCH_CONFIGURATIONS_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)
_MAX_COLLECTION_IDS = 5000 # max ffcids + aids allowed for one collection request
_MAX_COLLECTION_TAG_LENGTH = 100 # max length of collection tag
_MAX_DEPLOY_OR_SHUTDOWN_AIDS = 10000  # max number of aids to deploy or shutdown to in a single request

class ForensicsModule(BaseModule):
    """Module for creating forensics collection configurations, creating collections and deploying forensics collectors to endpoints."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Read-only tools
        self._add_tool(
            server=server,
            method=self.search_collections,
            name="search_collections",
        )

        self._add_tool(
            server=server,
            method=self.search_collectors,
            name="search_collectors",
        )

        self._add_tool(
            server=server,
            method=self.search_collections_by_ids,
            name="search_collections_by_ids",
        )

        self._add_tool(
            server=server,
            method=self.search_collectors_by_ids,
            name="search_collectors_by_ids",
        )

        self._add_tool(
            server=server,
            method=self.search_configurations_and_templates,
            name="search_configurations_and_templates",
        )

        self._add_tool(
                    server=server,
                    method=self.validate_configuration,
                    name="validate_configuration",
                )

        # Mutating tools
        self._add_tool(
            server=server,
            method=self.create_configuration,
            name="create_configuration",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )

        self._add_tool(
            server=server,
            method=self.update_configuration,
            name="update_configuration",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )

        self._add_tool(
            server=server,
            method=self.create_collection,
            name="create_collection",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )

        self._add_tool(
            server=server,
            method=self.deploy_collectors,
            name="deploy_collectors",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )

        self._add_tool(
            server=server,
            method=self.shutdown_collectors,
            name="shutdown_collectors",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )

        # Add more tools as needed

    def register_resources(self, server: FastMCP) -> None:
            """Register resources with the MCP server.
    
            Args:
                server: MCP server instance
            """
            collections_fql_resource = TextResource(
                uri=AnyUrl("falcon://forensics/collections/fql-guide"),
                name="falcon_search_collections_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`search_collections` tool."
                ),
                text=SEARCH_COLLECTIONS_FQL_DOCUMENTATION,
            )
    
            collectors_fql_resource = TextResource(
                uri=AnyUrl("falcon://forensics/collectors/fql-guide"),
                name="falcon_search_collectors_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`search_collectors` tool."
                ),
                text=SEARCH_COLLECTORS_FQL_DOCUMENTATION,
            )

            configurations_fql_resource = TextResource(
                uri=AnyUrl("falcon://forensics/configurations/fql-guide"),
                name="falcon_search_configurations_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`search_collectors` tool."
                ),
                text=SEARCH_CONFIGURATIONS_FQL_DOCUMENTATION,
            )

            configurations_model_resource = TextResource(
                            uri=AnyUrl("falcon://forensics/configurations/model-guide"),
                            name="falcon_create_configurations_model_guide",
                            description=(
                                "Contains the guide for the create configuration body of the "
                                "`create_configuration` tool."
                            ),
                            text=CONFIGURATIONS_MODEL_GUIDE,
                        )

            
    
            self._add_resource(server, collections_fql_resource)
            self._add_resource(server, collectors_fql_resource)
            self._add_resource(server, configurations_fql_resource)
            self._add_resource(server, configurations_model_resource)

    def search_collections(
        self,
        ids: list[str] | None = Field(
            default=None,
            description="Optional collection IDs to retrieve details for.",
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See "
                "`falcon://forensics/collections/fql-guide` for syntax."
            ),
            examples=[
                "platform:'windows'",
                "state:'complete'",
                "collection_tag:'foo'",
                "collection_tag:*'*bar'",
            ],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=500,
            description="The maximum records to return. [1-500]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str = Field(
            default="last_modified_timestamp.desc",
            description=dedent("""
                Sort collections using these options:

                modified_timestamp: when the collection was last modified
                created_timestamp: when the collection was created
                collection_tag: the collection tag used when the collection was created
                deadline: when the collection deadline expires
                priority: the 1-10 priority of the collection. 10 is highest priority
                state: the state the collection is in, e.g. complete, in progress, pending

                Each was verified to reorder results. Sort either asc (ascending)
                or desc (descending), using the dot separator ('name.desc').

                Examples: 'last_modified_timestamp.desc', 'priority.desc'
            """).strip(),
            examples=["last_modified_timestamp.desc", "collection_tag.asc"],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for Falcon Forensics Collections in your CrowdStrike environment.

        Use this to find a collection to inspect, filtering on platform, state,
        ffcid, aid, priority, collection tag, config_id or session_id. Consult
        falcon://forensics/collections/fql-guide before constructing filter
        expressions.
        """
        collections, pagination = self._base_search_with_meta(
            operation="GetCombinedCollectionsV1",
            search_params={
                "ids": ids,
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search collections",
        )

        if self._is_error(collections):
            return collections

        return self._build_pagination_envelope(collections or [], pagination, filter)

    def search_collectors(
            self,
            ids: list[str] | None = Field(
            description="optional collector IDs to retrieve details for."
            ),
            filter: str | None = Field(
                description="FQL filter expression. See `falcon://forensics/collectors/fql-guide`"
                                "for syntax.",
                examples=["filter=platform:'windows'", "state:'online'", "aid:'foo'", "ffcid:'bar'"],
            ),
            limit: int = Field(
                        default=10,
                        ge=1,
                        le=500,
                        description="The maximum records to return. [1-500]",
                    ),
                    offset: int | None = Field(
                        default=None,
                        description="The offset to start retrieving records from.",
                    ),
                    sort: str = Field(
                        default="seen_timestamp.desc",
                        description=dedent("""
                            Sort definitions using these options:
            
                            aid: the falcon sensor agent ID associated with the forensics collector
                            ffcid: the forensics collection unique identifier
                            state: the state the collector is in, e.g. offline, online, error
                            platform: platform of collector host, e.g. windows, linux, mac
                            modified_timestamp: the last modified time of a collector
                            seen_timestamp: the last time the collector was seen online
            
                            Each was verified to reorder results. Sort either asc (ascending)
                            or desc (descending), using the dot separator ('name.desc').
            
                            Examples: 'timestamp.desc', 'state.asc'
                        """).strip(),
                        examples={"last_modified_timestamp.desc", "platform.asc"},
                    ),
        ) -> list[dict[str, Any]] | dict[str, Any]:
            """Search for Falcon Forensics Collections in your CrowdStrike environment.
    
            Use this to find a collection to inspect, filtering on platform, state
            ffcid, aid, priority, collection tag, config_id or session_id. Consult
            falcon://forensics/collectors/fql-guide before constructing filter
            expressions
            """
            # Use base class methods for common patterns
            collections, pagination = self._base_search_with_meta(
                operation="GetCombinedCollectorsV1",
                search_params={
                    "ids": ids,
                    "filter": filter,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort,
                },
                error_message="Failed to search collectors",
            )
    
            if self._is_error(collections):
                return collections
    
            return self._build_pagination_envelope(collections or [], pagination, filter)

    def search_collections_by_ids(
        self,
        ids: list[str] = Field(
                    description="Collector IDs to retrieve details for."
            ),
    ) -> list[dict[str, Any]]:
        """Search for Forensics Collectors in your CrowdStrike environment.

        Use this to find collections by collection IDs. Consult falcon://forensics/collectors/fql-guide before constructing filter expressions. Returns full collection details including session ID, 
        aid, ffcid, platform, state, last seen.
        """

        # If we have collection IDs, get the details for each one
        if ids:
            details = self._base_get_by_ids(
                operation="GetCollectionsV1",
                ids=ids,
                id_key="ids",
            )

            # If handle_api_response returns an error dict instead of a list,
            # it means there was an error, so we return it wrapped in a list
            if self._is_error(details):
                return [details]

            return details

        return []

    def search_collectors_by_ids(
            self,
            ids: list[str] = Field(
                        description="collector IDs to retrieve details for."
                ),
        ) -> list[dict[str, Any]]:
            """Search for Forensics Collections in your CrowdStrike environment.
    
            Use this to find collectors by collector IDs. Consult falcon://forensics/collectors/fql-guide before constructing filter
            expressions. Returns full collector details including, aid, ffcid, state, last seen, last modified.
            """
    
            # If we have collection IDs, get the details for each one
            if ids:
                details = self._base_get_by_ids(
                    operation="GetCollectorsV1",
                    ids=ids,
                    id_key="ids",
                )
    
                # If handle_api_response returns an error dict instead of a list,
                # it means there was an error, so we return it wrapped in a list
                if self._is_error(details):
                    return [details]
    
                return details
    
            return []

    def search_configurations_and_templates(
        self,
        filter: str | None = Field(
            description="FQL filter expression. See `falcon://forensics/configurations/fql-guide`"
                            "for syntax.",
            examples=["filter=platform:'windows'", "name:'DeepWindowsScan'", "description:*'*Registry*'"],
        ),
        limit: int = Field(
                    default=10,
                    ge=1,
                    le=500,
                    description="The maximum records to return. [1-500]",
                ),
                offset: int | None = Field(
                    default=None,
                    description="The offset to start retrieving records from.",
                ),
                sort: str = Field(
                    default="last_modified_timestamp.desc",
                    description=dedent("""
                        Sort definitions using these options:
        
                        id: Unique identifier of config or template
                        name: Name of config or template
                        modified_timestamp: Last time the template or config was modified
                        is_template: whether the config is a template or not
        
                        Each was verified to reorder results. Sort either asc (ascending)
                        or desc (descending), using the dot separator ('name.desc').
        
                        Examples: 'modified_timestamp.desc', 'name.asc'
                    """).strip(),
                    examples={"modified_timestamp.desc", "name.asc"},
                ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for Falcon Forensics Configurations in your CrowdStrike environment.

        Use this to find a configuration to inspect, filtering on platform, name or description.
        Consult falcon://forensics/configurations/fql-guide before constructing filter expressions
        """
        # Use base class methods for common patterns
        configurations_and_templates, pagination = self._base_search_with_meta(
            operation="GetCombinedConfigsAndTemplatesV1",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search configurations",
        )

        if self._is_error(configurations_and_templates):
            return configurations_and_templates

        return self._build_pagination_envelope(configurations_and_templates or [], pagination, filter)

    _CONFIG_COLLECTIONS_DOC = """List of collection objects defining what this configuration gathers.

    Do NOT invent these. Call `search_configurations_and_templates` first, read an
    existing template's `collections` array, and adapt it. Template collections are
    the authoritative source for valid collection types and their options on each
    platform. See falcon://forensics/configurations/model-guide for field reference.
    
    Collections valid on one platform are often invalid on another — match the
    `platform` argument to the template you cloned from."""

    _COLLECTION_AIDS_DOC = """Agent IDs (AIDs) of Falcon-managed hosts to collect from.

    32-character hex strings. Get these from host search / device tools — do NOT
    invent them. At least one `aids` or `ffcids` entry is required.
    Every host must be on the same platform as the configuration being used;
    mismatched hosts are rejected individually and reported in `errors` while the
    rest of the run still schedules (partial success)."""

    _COLLECTION_FFCIDS_DOC = """Falcon Forensics Collector IDs (standalone, non-sensor collectors).

    32-character hex strings. Use this instead of `aids` for hosts running the
    standalone FFC rather than the Falcon sensor. May be combined with `aids`.
    The combined count of `aids` + `ffcids` must be between 1 and
    {max_ids} inclusive.""".format(max_ids=_MAX_COLLECTION_IDS)

    _COLLECTION_CONFIG_ID_DOC = """ID of the configuration defining WHAT gets collected.

    Call `search_configurations_and_templates` to find one, or create one with
    `create_configuration`. If omitted, the platform's default configuration is
    used and `platform` becomes REQUIRED."""

    def create_configuration(
        self,
        name: str = Field(
            description="Human-readable configuration name. Required, max 2000 characters.",
            examples=["DeepWindowsScan", "Linux IR Triage"],
            max_length=2000,
        ),
        platform: Literal["windows", "mac", "linux"] = Field(
            description="Target OS platform. Must match the collections supplied.",
        ),
        collections: list[dict[str, Any]] = Field(
            description=_CONFIG_COLLECTIONS_DOC,
        ),
        description: str | None = Field(
            default=None,
            description="Optional free-text description. Max 4000 characters.",
            max_length=4000,
        ),
        tag: str | None = Field(
            default=None,
            description=(
                "Optional tag applied to collections created from this configuration. "
                "Useful for grouping collections in later searches."
            ),
        ),
        is_default: bool | None = Field(
            default=None,
            description=(
                "Whether this becomes the default configuration for the platform. "
                "Omit to leave the current default unchanged."
            ),
        ),
    ) -> dict[str, Any]:
        """Create a new Falcon Forensics collection configuration.

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
        """
        error = _validate_save_config_request(name, platform, description)
        if error:
            return error

        body: dict[str, Any] = {
            "name": name,
            "platform": platform,
            "collections": collections,
        }
        if description is not None:
            body["description"] = description
        if tag is not None:
            body["tag"] = tag
        if is_default is not None:
            body["is_default"] = is_default

        response = self.client.command("ValidateConfigV1", body=body)
        return _classify_save_response(response, action="create")

    def validate_configuration(
        self,
        name: str = Field(
            description="Configuration name. Required, max 2000 characters.",
            max_length=2000,
        ),
        platform: Literal["windows", "mac", "linux"] = Field(
            description="Target OS platform. Must match the collections supplied.",
        ),
        collections: list[dict[str, Any]] = Field(
            description=_CONFIG_COLLECTIONS_DOC,
        ),
        description: str | None = Field(
            default=None,
            description="Optional description. Max 4000 characters.",
            max_length=4000,
        ),
        tag: str | None = Field(default=None, description="Optional collection tag."),
        is_default: bool | None = Field(
            default=None,
            description="Whether this would become the platform default.",
        ),
        config_id: str | None = Field(
            default=None,
            description=(
                "Only when validating an edit to an existing configuration. "
                "Omit when validating a new one."
            ),
        ),
    ) -> dict[str, Any]:
        """Validate a Forensics configuration without saving it.

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
        """
     
        error = _validate_save_config_request(name, platform, description)
        if error:
            return {
                "valid": False,
                "errors": [error],
                "error_types": ["request"],
                "validated_by": "client",
                "note": (
                    "Rejected by local request validation; server-side collector "
                    "validation did NOT run. Fix these fields and re-validate to "
                    "check the collections."
                ),
            }

        body = _build_save_config_body(
            name, platform, collections, description, tag, is_default, config_id
        )

        response = self.client.command(
            "ValidateConfigV1",
            body=body,
        )
        return _classify_validation_response(response)

    def _fetch_configuration(self, config_id: str) -> dict[str, Any]:
        """Retrieve a single configuration for read-modify-write merging."""
        existing = self._base_get_by_ids(
            operation="GetCombinedConfigsAndTemplatesV1",
            ids=[config_id],
            id_key="ids",
        )
        if self._is_error(existing):
            return existing
        if not existing:
            return _format_error_response(
                f"No configuration found with id '{config_id}'. Look up the correct "
                f"id with search_configurations_and_templates before updating."
            )
        return existing[0]

    def update_configuration(
        self,
        config_id: str = Field(
            description=(
                "ID of the existing configuration to update. Required. Obtain it "
                "from search_configurations_and_templates — never guess it, as a "
                "wrong id overwrites a different configuration."
            ),
        ),
        name: str | None = Field(
            default=None,
            max_length=2000,
            description="New name. Omit to keep the current name.",
        ),
        description: str | None = Field(
            default=None,
            max_length=4000,
            description=(
                "New description. Omit to keep the current one; pass an empty "
                "string to clear it."
            ),
        ),
        collections: list[dict[str, Any]] | None = Field(
            default=None,
            description=(
                "Replacement collections array. This REPLACES the existing array "
                "entirely — it is not merged per-entry. To add or remove one entry, "
                "read the current array first and submit the full modified list. "
                "Omit to leave collections untouched. " + _CONFIG_COLLECTIONS_DOC
            ),
        ),
        platform: Literal["windows", "mac", "linux"] | None = Field(
            default=None,
            description=(
                "New target platform. Changing this requires supplying a matching "
                "`collections` array, since collections are platform-specific. "
                "Omit to keep the current platform."
            ),
        ),
        tag: str | None = Field(
            default=None,
            description=(
                "New collection tag. Omit to keep the current one; pass an empty "
                "string to clear it."
            ),
        ),
        is_default: bool | None = Field(
            default=None,
            description=(
                "Set or unset this configuration as the platform default. Omit to "
                "leave the current setting unchanged. Setting it true may remove "
                "default status from whichever configuration currently holds it."
            ),
        ),
    ) -> dict[str, Any]:
        """Modify an existing Falcon Forensics configuration.

        Supply only the fields you want to change; current values are preserved
        for any field you omit. The underlying API is a full-document overwrite,
        so this tool reads the configuration first and merges your changes — which
        means a concurrent edit by someone else between the read and the write can
        be lost.

        `collections` is replaced wholesale, not merged. Read the existing array,
        modify it, and submit the complete result.

        Changing `name` to one already used by another configuration fails with a
        duplicate-name conflict and changes nothing.
        """
        if not config_id:
            return _format_error_response("'config_id' is required to update a configuration")

        existing = self._fetch_configuration(config_id)
        if self._is_error(existing):
            return existing

        # Templates are the reference material the model guide tells agents to
        # clone. Mutating one in place is almost never the intent.
        if existing.get("is_template"):
            return _format_error_response(
                f"Configuration '{config_id}' is a template. Updating a template "
                f"changes the reference others clone from. If you meant to create "
                f"a variant, copy its collections into create_configuration instead."
            )

        merged_platform = platform if platform is not None else existing.get("platform")
        if (
            platform is not None
            and platform != existing.get("platform")
            and collections is None
        ):
            return _format_error_response(
                f"Cannot change platform from '{existing.get('platform')}' to "
                f"'{platform}' without also supplying `collections`. The existing "
                f"collections are specific to the old platform and would be invalid. "
                f"Clone a template for the target platform and pass its collections."
            )

        # Full overwrite: every field must be sent, taking the existing value
        # wherever the caller did not supply one. Omission here means deletion.
        merged_name = name if name is not None else existing.get("name")
        merged_collections = (
            collections if collections is not None else existing.get("collections") or []
        )
        merged_description = (
            description if description is not None else existing.get("description")
        )
        merged_tag = tag if tag is not None else existing.get("tag")
        merged_is_default = (
            is_default if is_default is not None else existing.get("is_default")
        )

        error = _validate_save_config_request(merged_name, merged_platform, merged_description)
        if error:
            return error

        body = _build_save_config_body(
            name=merged_name,
            platform=merged_platform,
            collections=merged_collections,
            description=merged_description,
            tag=merged_tag,
            is_default=merged_is_default,
            config_id=config_id,
        )

        response = self.client.command("PutConfigsV1", body=body)
        return _classify_save_response(response, action="update")

    def create_collection(
        self,
        aids: list[str] | None = Field(
            default=None,
            description=_COLLECTION_AIDS_DOC,
            examples=[["1234567890abcdef1234567890abcdef"]],
            max_length=_MAX_COLLECTION_IDS,
        ),
        ffcids: list[str] | None = Field(
            default=None,
            description=_COLLECTION_FFCIDS_DOC,
            max_length=_MAX_COLLECTION_IDS,
        ),
        config_id: str | None = Field(
            default=None,
            description=_COLLECTION_CONFIG_ID_DOC,
        ),
        platform: Literal["windows", "mac", "linux"] | None = Field(
            default=None,
            description=(
                "Target OS platform. Required only when `config_id` is omitted "
                "(selects the platform default configuration). When `config_id` is "
                "supplied, the configuration's platform is authoritative and this "
                "value is ignored."
            ),
        ),
        priority: Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10] | None = Field(
            default=5,
            description=(
                "Scheduling priority for the collection run."
            ),
        ),
        deadline: str | None = Field(
            default=None,
            description=(
                "RFC3339/ISO-8601 UTC timestamp after which the collection will no "
                "longer be attempted on hosts that have not yet checked in, e.g. "
                "'2026-11-03T18:00:00Z'. Omit for default 7 day deadline."
            ),
        ),
        collection_tag: str | None = Field(
            default=None,
            description=(
                "Optional tag applied to every collection in this run. Useful for "
                "grouping and for later retrieval via collection searches. "
                f"Max {_MAX_COLLECTION_TAG_LENGTH} characters."
            ),
            max_length=_MAX_COLLECTION_TAG_LENGTH,
        ),
        self_destruct: bool | None = Field(
            default=None,
            description=(
                "If true, the collector deletes itself from the host after the "
                "collection completes."
            ),
        ),
    ) -> dict[str, Any]:
        """Schedule a Falcon Forensics collection run against a set of hosts.

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
        """
        error = _validate_new_collections_request(
            aids, ffcids, platform, config_id, collection_tag
        )
        if error:
            return error

        body: dict[str, Any] = {
            "aids": aids or [],
            "ffcids": ffcids or [],
        }
        if config_id is not None:
            body["config_id"] = config_id
        if platform is not None:
            body["platform"] = platform
        if priority is not None:
            body["priority"] = priority
        if deadline is not None:
            body["deadline"] = deadline
        if collection_tag is not None:
            body["collection_tag"] = collection_tag
        if self_destruct is not None:
            body["self_destruct"] = self_destruct

        return self._base_create(
            operation="PostCollectionsV1",
            body=body,
            error_message="Failed to create collection",
        )

    def deploy_collectors(
        self,
        aids: list[str] = Field(
            description=(
                "Falcon agent IDs (AIDs) of hosts to deploy the forensics collector to. "
                "32-character hex strings. Obtain these from host search or an existing "
                "collection — never construct or guess them. "
                f"Maximum {_MAX_DEPLOY_OR_SHUTDOWN_AIDS} per call."
            ),
        ),
        queue_offline: bool = Field(
            default=False,
            description=(
                "If true, queue the deployment for hosts that are currently offline so "
                "it runs when they next connect. If false, offline hosts are not deployed to "
                "when session initialization fails due to the host being offline. "
            ),
        ),
        no_proxy: bool = Field(
            default=False,
            description=(
                "Explicitly deploy without a proxy. Cannot be combined with "
                "proxy_host/proxy_port."
            ),
        ),
        proxy_host: str | None = Field(
            default=None,
            description=(
                "Proxy hostname for the collector to use. Must be supplied together "
                "with proxy_port. Omit both to use the host's default behaviour."
            ),
        ),
        proxy_port: int | None = Field(
            default=None,
            ge=1,
            le=65535,
            description="Proxy port. Must be supplied together with proxy_host.",
        ),
    ) -> dict[str, Any]:
        """Deploy the Falcon Forensics collector to specific hosts.

        This deploys and executes the collector on live endpoints — a real action on
        production machines, not a configuration change. Confirm the AID list is
        correct and intended before calling.

        Proxy settings are all-or-nothing: supply both proxy_host and proxy_port,
        or set no_proxy=true, or omit all three for default behaviour.

        Returns the collectors that were actually deployed. Compare that list
        against the AIDs you requested — hosts can be silently omitted if they are
        already have an active collector session, are already in a deploying state or
        are unknown aids.
        """
        error = _validate_deploy_agents(aids, no_proxy, proxy_host, proxy_port)
        if error:
            return error

        body: dict[str, Any] = {
            "aids": [a.strip() for a in aids],
            "queue_offline": queue_offline,
        }
        if no_proxy:
            body["no_proxy"] = True
        if proxy_host is not None:
            body["proxy_host"] = proxy_host
        if proxy_port is not None:
            body["proxy_port"] = proxy_port

        response = self.client.command("PostDeployV1", body=body)
        return _classify_deploy_response(response, requested=body["aids"])

    def shutdown_collectors(
        self,
        aids: list[str] | None = Field(
            default=None,
            description=(
                "Falcon agent IDs (AIDs) of hosts whose collectors should be shut "
                "down. 32-character hex strings from search_collectors. "
                f"Combined with ffcids, maximum {_MAX_DEPLOY_OR_SHUTDOWN_AIDS} per call."
            ),
        ),
        ffcids: list[str] | None = Field(
            default=None,
            description=(
                "Forensics collector IDs (FFCIDs) to shut down. Use these to target "
                "a specific collector instance when a host has more than one. "
                "Obtain from search_collectors."
            ),
        ),
        self_destruct: bool = Field(
            default=False,
            description=(
                "If true, the collector uninstalls itself from the host after "
                "shutting down, rather than remaining installed and idle. "
                "Redeploying later requires a fresh deploy_collectors call."
            ),
        ),
        force: bool = Field(
            default=False,
            description=(
                "Force shutdown of collectors that are not cleanly stoppable. May "
                "abandon an in-progress collection and lose its uncollected data."
            ),
        ),
    ) -> dict[str, Any]:
        """Shut down running Falcon Forensics collectors on hosts.

        This stops live collectors on production endpoints and ends any collection
        in progress if force is set to True. Always target specific hosts with `aids` or `ffcids`, which
        you should obtain from `search_collectors` — never guess them.

        `self_destruct` additionally deletes the collector binary. `force` can abandon
        an in-progress collection. Both default to false; leave them there unless specifically required.

        Returns the collectors that were shut down. A 'no collectors in progress'
        result means there was nothing running to stop and no state changed.
        """
        error = _validate_shutdown_agents(aids, ffcids)
        if error:
            return error

        body: dict[str, Any] = {
            "aids": [a.strip() for a in (aids or [])],
            "ffcids": [f.strip() for f in (ffcids or [])],
            "self_destruct": self_destruct,
            "force": force,
        }

        response = self.client.command("PostCollectorsV1", body=body)
        return _classify_shutdown_response(
            response,
            requested=body["aids"] + body["ffcids"],
            self_destruct=self_destruct,
        )

def _validate_save_config_request(
    name: str,
    platform: str,
    description: str | None,
) -> dict[str, Any] | None:
    if not name:
        return _format_error_response("'name' is a required field")
    if len(name) > 2000:
        return _format_error_response("'name' should be less than 2000 characters")
    if description is not None and len(description) > 4000:
        return _format_error_response("'description' should be less than 4000 characters")
    if platform not in ("windows", "mac", "linux"):
        return _format_error_response(
            "'platform' must be one of 'windows', 'mac', or 'linux'"
        )
    return None

def _classify_validation_response(response: dict[str, Any]) -> dict[str, Any]:
    """Map StructuredResponseV1 onto a validation verdict.

    200 + no errors        -> valid
    400                    -> invalid; errors are the verdict
    anything else (401/403/500) -> no verdict was produced; tool error
    """
    status = response.get("status_code")
    body = response.get("body") or {}
    errors = body.get("errors") or []
    trace_id = (body.get("meta") or {}).get("trace_id")

    if status == 200 and not errors:
        return {
            "valid": True,
            "errors": [],
            "validated_by": "server",
            "trace_id": trace_id,
        }

    if status == 400:
        return {
            "valid": False,
            "errors": errors,  # verbatim: preserves field paths / collector names
            "error_types": sorted({e["type"] for e in errors if e.get("type")}),
            "validated_by": "server",
            "trace_id": trace_id,
        }

    # 500 w/ ValidationErrorType means the validator itself failed — the config
    # may well be fine. Reporting valid=False when the collection is actually valid
    # is misleading.
    return _format_error_response(
        f"Validation did not complete (HTTP {status}). The configuration was "
        f"neither accepted nor rejected; do not treat this as invalid.",
        details={"errors": errors, "trace_id": trace_id},
    )

def _build_save_config_body(
    name: str,
    platform: str,
    collections: list[dict[str, Any]],
    description: str | None = None,
    tag: str | None = None,
    is_default: bool | None = None,
    config_id: str | None = None,
) -> dict[str, Any]:
    """Build a Save Config body.

    Omit `config_id` for create/validate-new
    """
    body: dict[str, Any] = {
        "name": name,
        "platform": platform,
        "collections": collections,
    }
    if config_id is not None:
        body["id"] = config_id
    if description is not None:
        body["description"] = description
    if tag is not None:
        body["tag"] = tag
    if is_default is not None:
        body["is_default"] = is_default
    return body

def _validate_new_collections_request(
    aids: list[str] | None,
    ffcids: list[str] | None,
    platform: str | None,
    config_id: str | None,
    collection_tag: str | None,
) -> dict[str, Any] | None:
    """Pre-flight validation mirroring NewCollectionsRequest.Validate (POST path).

    Returns an error payload dict on failure, otherwise None.
    """
    aids = aids or []
    ffcids = ffcids or []
    id_count = len(aids) + len(ffcids)

    if id_count == 0:
        return _format_error_response(
            "At least one agent ID is required: supply `aids` and/or `ffcids`."
        )
    if id_count > _MAX_COLLECTION_IDS:
        return _format_error_response(
            f"Too many target IDs: {id_count} supplied, maximum is {_MAX_COLLECTION_IDS}."
        )

    if not config_id and not platform:
        return _format_error_response(
            "`platform` is required when `config_id` is omitted, because the "
            "platform's default configuration is used."
        )

    if collection_tag and len(collection_tag) > _MAX_COLLECTION_TAG_LENGTH:
        return _format_error_response(
            f"`collection_tag` is {len(collection_tag)} characters, maximum is "
            f"{_MAX_COLLECTION_TAG_LENGTH}."
        )

    return None

def _validate_deploy_agents(
    aids: list[str],
    no_proxy: bool,
    proxy_host: str | None,
    proxy_port: int | None,
) -> dict[str, Any] | None:
    """Validate the deploy agents request"""
    if not aids:
        return _format_error_response("'aids' is required and must contain at least one agent ID")
    if len(aids) > _MAX_DEPLOY_OR_SHUTDOWN_AIDS:
        return _format_error_response(
            f"Too many agent IDs: {len(aids)} supplied, maximum is {_MAX_DEPLOY_OR_SHUTDOWN_AIDS}. "
            f"Split into batches."
        )

    has_proxy = bool(proxy_host) or proxy_port is not None
    if no_proxy and has_proxy:
        return _format_error_response(
            "'no_proxy' cannot be combined with 'proxy_host' or 'proxy_port'. "
            "Either set no_proxy=true, or supply both proxy_host and proxy_port."
        )
    if proxy_host and proxy_port is None:
        return _format_error_response(
            "'proxy_host' requires 'proxy_port' — supply both or neither."
        )
    if proxy_port is not None and not proxy_host:
        return _format_error_response(
            "'proxy_port' requires 'proxy_host' — supply both or neither."
        )
    if proxy_port is not None and not (1 <= proxy_port <= 65535):
        return _format_error_response(
            f"'proxy_port' must be between 1 and 65535, got {proxy_port}."
        )
    return None

def _classify_deploy_response(
    response: dict[str, Any], requested: list[str]
) -> dict[str, Any]:
    status = response.get("status_code")
    body = response.get("body") or {}
    errors = body.get("errors") or []
    resources = body.get("resources") or []
    trace_id = (body.get("meta") or {}).get("trace_id")

    if status == 200 and not errors:
        deployed = {r["aid"].lower() for r in resources if r.get("aid")}
        missing = [a for a in requested if a.lower() not in deployed]
        result: dict[str, Any] = {
            "deployed_count": len(deployed),
            "requested_count": len(requested),
            "collectors": resources,
            "trace_id": trace_id,
        }
        if missing:
            result["not_deployed"] = missing
            result["warning"] = (
                f"{len(missing)} of {len(requested)} requested hosts were not "
                f"deployed to. Likely unknown AIDs, already online or deploying. "
                f"Verify these AIDs before retrying."
            )
        return result

    # 404 = unknown AIDs; 400 = ErrNoValidAIDs / bad proxy / over MaxIDs.
    # Generic 500 "failed to deploy" is deliberately opaque server-side —
    # the trace_id is the only handle for support.
    return _format_error_response(
        f"Deployment failed (HTTP {status}). No collectors were deployed."
        if not resources
        else f"Deployment partially failed (HTTP {status}).",
        details={"errors": errors, "collectors": resources, "trace_id": trace_id},
    )

def _validate_shutdown_agents(
    aids: list[str] | None,
    ffcids: list[str] | None,
) -> dict[str, Any] | None:
    """Validate shutdown agents request. Must contain at least one ffcid or aid
    """
    aids = aids or []
    ffcids = ffcids or []
    total = len(aids) + len(ffcids)

    if total == 0:
        return _format_error_response(
            "Refusing to shut down collectors: no 'aids' or 'ffcids' supplied. "
            "Look up specific hosts with search_collectors and pass "
            "them explicitly."
        )
    
    if total > _MAX_DEPLOY_OR_SHUTDOWN_AIDS:
        return _format_error_response(
            f"Too many target IDs: {len(aids)} aids + {len(ffcids)} ffcids = {total}, "
            f"maximum is {_MAX_DEPLOY_OR_SHUTDOWN_AIDS}. Split into batches."
        )

    return None

def _classify_shutdown_response(
    response: dict[str, Any],
    requested: list[str],
    self_destruct: bool,
) -> dict[str, Any]:
    status = response.get("status_code")
    body = response.get("body") or {}
    errors = body.get("errors") or []
    resources = body.get("resources") or []
    trace_id = (body.get("meta") or {}).get("trace_id")

    if status == 200 and not errors:
        result: dict[str, Any] = {
            "shutdown_count": len(resources),
            "collectors": resources,
            "self_destruct": self_destruct,
            "trace_id": trace_id,
        }
        if requested:
            # Resources are deduplicated server-side, so this
            # diff flags unmatched targets.
            returned = {
                v.lower()
                for r in resources
                for v in (r.get("aid"), r.get("ffcid"))
                if v
            }
            missing = [i for i in requested if i.lower() not in returned]
            if missing:
                result["not_shutdown"] = missing
                result["warning"] = (
                    f"{len(missing)} of {len(requested)} requested targets were not "
                    f"shut down. Likely no collector was running on them, or the ID "
                    f"was not found. Verify with search_collectors."
                )
        return result

    # 404 = No im progress collectors / No Collector IDs: nothing was running.
    # Not a failure, and NOT a reason to retry with force=true.
    if status == 404:
        return {
            "shutdown_count": 0,
            "collectors": [],
            "no_collectors_in_progress": True,
            "message": (
                "No running collectors matched the request, so nothing was shut "
                "down and no state changed. This is not an error. Do not retry "
                "with force=true — check current collector state with "
                "search_collectors instead."
            ),
            "trace_id": trace_id,
        }

    return _format_error_response(
        f"Shutdown failed (HTTP {status})."
        if not resources
        else f"Shutdown partially failed (HTTP {status}).",
        details={"errors": errors, "collectors": resources, "trace_id": trace_id},
    )

def _classify_save_response(
    response: dict[str, Any], action: str
) -> dict[str, Any]:
    status = response.get("status_code")
    body = response.get("body") or {}
    errors = body.get("errors") or []
    resources = body.get("resources") or []
    trace_id = (body.get("meta") or {}).get("trace_id")

    if status == 200 and not errors and resources:
        return {"configuration": resources[0], "trace_id": trace_id}

    if status == 200 and not errors and not resources:
        return _format_error_response(
            f"The {action} returned success but no configuration, so it is "
            f"unclear whether the change was applied. Re-read the configuration "
            f"with search_configurations_and_templates to confirm its current "
            f"state before retrying.",
            details={"trace_id": trace_id},
        )

    if status == 409:
        return _format_error_response(
            "A configuration with that name already exists. Nothing was changed. "
            "Choose a different name.",
            details={"errors": errors, "trace_id": trace_id},
        )

    if status == 400:
        return _format_error_response(
            f"The {action} was rejected by validation; nothing was changed. "
            f"Fix the reported fields or collections and retry.",
            details=_classify_validation_response(response),
        )

    return _format_error_response(
        f"Failed to {action} configuration (HTTP {status}).",
        details={"errors": errors, "trace_id": trace_id},
    )