"""
Forensics module for Falcon MCP Server

This module provides tools for interacting with the Falcon Forensics API endpoints. Creating configurations and dispatching collections to endpoints
"""
from textwrap import dedent
from typing import Any

from mcp.server import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field
from pydantic import Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.forensics import (
    SEARCH_COLLECTIONS_FQL_DOCUMENTATION,
    SEARCH_COLLECTORS_FQL_DOCUMENTATION,
    SEARCH_CONFIGURATIONS_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)

class ForensicsModule(BaseModule):
    """Module for creating forensics collection configurations, creating collections and deploying forensics collectors to endpoints."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Read-only tool — default annotations apply automatically
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

        # Mutating tool — must override annotations
        self._add_tool(
            server=server,
            method=self.your_create_method,
            name="your_create_name",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
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
                name="falcon_search_collectors_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`search_collectors` tool."
                ),
                text=SEARCH_CONFIGURATIONS_FQL_DOCUMENTATION,
            )
    
            self._add_resource(server, collections_fql_resource)
            self._add_resource(server, collectors_fql_resource)
            self._add_resource(server, configurations_fql_resource)

    def search_collections(
        self,
        ids: list[str] = Field(
                    description="optional collection IDs to retrieve details for."
                    ),
        filter: str = Field(
            description="FQL filter expression. See `falcon://forensics/collections/fql-guide`"
                            "for syntax.",
            examples=["filter=platform:'windows'", "state:'complete'", "collection_tag:'foo'", "collection_tag:*'*bar'"],
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
        
                        modified_timestamp: when the collection was last modified
                        created_timestamp: when the collection was created
                        collection_tag: the collection tag used when the collection was created
                        deadline: when the collection deadline expires
                        priority: the 1-10 priority of the collection. 10 is highest priority
                        state: the state the collection is in, e.g. complete, im progress, pending
        
                        Each was verified to reorder results. Sort either asc (ascending)
                        or desc (descending), using the dot separator ('name.desc').
        
                        Examples: 'last_modified_timestamp.desc', 'name.asc'
                    """).strip(),
                    examples={"last_modified_timestamp.desc", "collection_tag.asc"},
                ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for Falcon Forensics Collections in your CrowdStrike environment.

        Use this to find a collection to inspect, filtering on platform, state
        ffcid, aid, priority, collection tag, config_id or session_id. Consult
        falcon://forensics/search/fql-guide before constructing filter
        expressions
        """
        # Use base class methods for common patterns
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
            ids: list[str] = Field(
            description="optional collector IDs to retrieve details for."
            ),
            filter: str = Field(
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
                            seen timestamp: the last time the collector was seen online
            
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
            falcon://forensics/search/fql-guide before constructing filter
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
                error_message="Failed to search collections",
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
    
            Use this to find collectors by collector IDs. Consult falcon://forensics/search/fql-guide before constructing filter
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
        filter: str = Field(
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