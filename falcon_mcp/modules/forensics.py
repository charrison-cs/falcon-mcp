"""
Forensics module for Falcon MCP Server

This module provides tools for interacting with the Falcon Forensics API endpoints. Creating configurations and dispatching collections to endpoints
"""
from textwrap import dedent
from typing import Any

from mcp.server import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

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

    def search_collections(
        self,
        filter: str = Field(
            description="FQL filter expression. See `falcon://forensics/workflow-definitions/fql-guide` "
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
        falcon://fusion/workflow-definitions/fql-guide before constructing filter
        expressions
        """
        # Use base class methods for common patterns
        collections, pagination = self._base_search_with_meta(
            operation="GetCombinedCollectionsV1",
            search_params={
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