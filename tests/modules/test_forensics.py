"""
Tests for the Forensics module.
"""

import unittest
from unittest.mock import patch

from mcp.types import ToolAnnotations

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.forensics import ForensicsModule
from tests.modules.utils.test_modules import TestModules

_CREATE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)

_DESTRUCTIVE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=False,
)

_DESTRUCTIVE_NON_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)

_AID_A = "1234567890abcdef1234567890abcdef"
_AID_B = "fedcba0987654321fedcba0987654321"
_CONFIG_ID = "11111111-2222-3333-4444-555555555555"

_WINDOWS_COLLECTIONS = [
    {"name": "Registry Hives", "collector": "registry", "options": {"hives": ["SYSTEM"]}}
]


def _existing_config(**overrides):
    """A stored configuration as returned by the by-ID read."""
    config = {
        "id": _CONFIG_ID,
        "name": "Windows IR Triage",
        "platform": "windows",
        "description": "original description",
        "tag": "original-tag",
        "is_default": True,
        "is_template": False,
        "collections": _WINDOWS_COLLECTIONS,
    }
    config.update(overrides)
    return config


class TestForensicsModule(TestModules):
    """Test cases for the Forensics module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(ForensicsModule)

    # --- Registration ---

    def test_register_tools(self):
        """All forensics tools register under the falcon_ prefix."""
        expected_tools = [
            "falcon_search_collections",
            "falcon_search_collectors",
            "falcon_search_collections_by_ids",
            "falcon_search_collectors_by_ids",
            "falcon_search_configurations_and_templates",
            "falcon_validate_configuration",
            "falcon_create_configuration",
            "falcon_update_configuration",
            "falcon_create_collection",
            "falcon_deploy_collectors",
            "falcon_shutdown_collectors",
        ]
        self.assert_tools_registered(expected_tools)

    def test_register_resources(self):
        """FQL guides and the configuration model guide are registered."""
        expected_resources = [
            "falcon_search_collections_fql_guide",
            "falcon_search_collectors_fql_guide",
            "falcon_search_configurations_fql_guide",
            "falcon_create_configurations_model_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_read_only_tools_use_default_annotations(self):
        """Searches and validate must stay read-only so clients do not gate them.

        validate_configuration is the iteration path for an untyped `options`
        field; if it registered as a write it would consume an approval per
        attempt and callers would skip it.
        """
        self.module.register_tools(self.mock_server)
        for name in (
            "falcon_search_collections",
            "falcon_search_collectors",
            "falcon_search_collections_by_ids",
            "falcon_search_collectors_by_ids",
            "falcon_search_configurations_and_templates",
            "falcon_validate_configuration",
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)

    # def test_create_tools_are_non_destructive(self):
    #     """Creates add new records and cannot overwrite, so destructiveHint is False."""
    #     self.module.register_tools(self.mock_server)
    #     self.assert_tool_annotations("falcon_create_configuration", _CREATE_ANNOTATIONS)
    #     self.assert_tool_annotations("falcon_create_collection", _CREATE_ANNOTATIONS)

    # def test_update_configuration_is_destructive_and_idempotent(self):
    #     """Update overwrites in place with no version history.

    #     idempotentHint is True because the same merged body applied twice leaves
    #     the same stored document.
    #     """
    #     self.module.register_tools(self.mock_server)
    #     self.assert_tool_annotations(
    #         "falcon_update_configuration", _DESTRUCTIVE_IDEMPOTENT
    #     )

    # def test_deploy_is_destructive_and_not_idempotent(self):
    #     """Deploy executes software on live endpoints; a repeat call is not a no-op."""
    #     self.module.register_tools(self.mock_server)
    #     self.assert_tool_annotations(
    #         "falcon_deploy_collectors", _DESTRUCTIVE_NON_IDEMPOTENT
    #     )

    # def test_shutdown_is_destructive(self):
    #     """Shutdown terminates in-flight collections and can uninstall collectors."""
    #     self.module.register_tools(self.mock_server)
    #     self.assert_tool_annotations(
    #         "falcon_shutdown_collectors", _DESTRUCTIVE_IDEMPOTENT
    #     )

    # # --- search_collections ---

    # def test_search_collections_success(self):
    #     """Records come back inside the pagination envelope with the filter echoed."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [
    #                 {"ffcid": "f1", "aid": _AID_A, "state": "complete"},
    #                 {"ffcid": "f2", "aid": _AID_B, "state": "in progress"},
    #             ],
    #             "meta": {"pagination": {"offset": 0, "limit": 10, "total": 2}},
    #         },
    #     }

    #     result = self.module.search_collections(
    #         ids=None,
    #         filter="state:'complete'",
    #         limit=10,
    #         offset=None,
    #         sort="last_modified_timestamp.desc",
    #     )

    #     self.assertEqual(len(result["results"]), 2)
    #     self.assertEqual(result["filter_used"], "state:'complete'")
    #     self.assert_pagination(result, total=2)

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "GetCombinedCollectionsV1")
    #     self.assertEqual(
    #         kwargs["parameters"],
    #         {
    #             "filter": "state:'complete'",
    #             "limit": 10,
    #             "sort": "last_modified_timestamp.desc",
    #         },
    #     )

    # def test_search_collections_drops_none_params(self):
    #     """ids and offset are omitted from the query string when not supplied."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
    #     }

    #     self.module.search_collections(
    #         ids=None, filter=None, limit=10, offset=None, sort="priority.desc"
    #     )

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertNotIn("ids", kwargs["parameters"])
    #     self.assertNotIn("offset", kwargs["parameters"])
    #     self.assertNotIn("filter", kwargs["parameters"])

    # def test_search_collections_forwards_offset(self):
    #     """offset reaches the API when supplied."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
    #     }

    #     self.module.search_collections(
    #         ids=None, filter=None, limit=25, offset=50, sort="priority.desc"
    #     )

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["parameters"]["offset"], 50)

    # def test_search_collections_empty_returns_envelope(self):
    #     """No matches is still an envelope, not an error."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [],
    #             "meta": {"pagination": {"offset": 0, "limit": 10, "total": 0}},
    #         },
    #     }

    #     result = self.module.search_collections(
    #         ids=None,
    #         filter="state:'nope'",
    #         limit=10,
    #         offset=None,
    #         sort="last_modified_timestamp.desc",
    #     )

    #     self.assertEqual(result["results"], [])
    #     self.assert_pagination(result, total=0)

    # def test_search_collections_error(self):
    #     """A 403 surfaces as an error dict rather than an empty result set."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 403,
    #         "body": {"errors": [{"code": 403, "message": "access denied"}]},
    #     }

    #     result = self.module.search_collections(
    #         ids=None, filter=None, limit=10, offset=None, sort="priority.desc"
    #     )

    #     self.assertIn("error", result)

    # # --- search_collectors ---

    # def test_search_collectors_success(self):
    #     """Collectors use their own operation and default sort."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [{"ffcid": "f1", "aid": _AID_A, "state": "online"}],
    #             "meta": {"pagination": {"offset": 0, "limit": 10, "total": 1}},
    #         },
    #     }

    #     result = self.module.search_collectors(
    #         ids=None,
    #         filter="state:'online'",
    #         limit=10,
    #         offset=None,
    #         sort="seen_timestamp.desc",
    #     )

    #     self.assertEqual(result["results"][0]["state"], "online")
    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "GetCombinedCollectorsV1")
    #     self.assertEqual(kwargs["parameters"]["sort"], "seen_timestamp.desc")

    # def test_search_collectors_error_message_names_collectors(self):
    #     """The error text must not say 'collections' — it misroutes debugging."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 500,
    #         "body": {"errors": [{"code": 500, "message": "boom"}]},
    #     }

    #     result = self.module.search_collectors(
    #         ids=None, filter=None, limit=10, offset=None, sort="seen_timestamp.desc"
    #     )

    #     self.assertIn("error", result)
    #     self.assertIn("collectors", result["error"].lower())

    # # --- by-ID reads ---

    # def test_search_collections_by_ids_success(self):
    #     """Full records are returned unwrapped as a list."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "f1", "aid": _AID_A}]},
    #     }

    #     result = self.module.search_collections_by_ids(ids=["f1"])

    #     self.assertEqual(result[0]["ffcid"], "f1")
    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "GetCollectionsV1")
    #     self.assertEqual(kwargs["parameters"]["ids"], ["f1"])

    # def test_search_collections_by_ids_empty_list_skips_api(self):
    #     """An empty id list short-circuits without a wasted call."""
    #     result = self.module.search_collections_by_ids(ids=[])

    #     self.assertEqual(result, [])
    #     self.mock_client.command.assert_not_called()

    # def test_search_collectors_by_ids_success(self):
    #     """Collectors by ID use the collector operation."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "c1", "aid": _AID_A}]},
    #     }

    #     result = self.module.search_collectors_by_ids(ids=["c1"])

    #     self.assertEqual(result[0]["ffcid"], "c1")
    #     args, _ = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "GetCollectorsV1")

    # def test_search_collectors_by_ids_error_wrapped_in_list(self):
    #     """An error is wrapped so the declared list return type holds."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 404,
    #         "body": {"errors": [{"code": 404, "message": "collector 'c1' not found"}]},
    #     }

    #     result = self.module.search_collectors_by_ids(ids=["c1"])

    #     self.assertIsInstance(result, list)
    #     self.assertIn("error", result[0])

    # # --- search_configurations_and_templates ---

    # def test_search_configurations_success(self):
    #     """Configurations and templates share one combined endpoint."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [_existing_config(), _existing_config(is_template=True)],
    #             "meta": {"pagination": {"offset": 0, "limit": 10, "total": 2}},
    #         },
    #     }

    #     result = self.module.search_configurations_and_templates(
    #         filter="platform:'windows'",
    #         limit=10,
    #         offset=None,
    #         sort="last_modified_timestamp.desc",
    #     )

    #     self.assertEqual(len(result["results"]), 2)
    #     args, _ = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "GetCombinedConfigsAndTemplatesV1")

    # # --- create_configuration: client-side validation ---

    # def _create(self, **overrides):
    #     kwargs = {
    #         "name": "Windows IR Triage",
    #         "platform": "windows",
    #         "collections": _WINDOWS_COLLECTIONS,
    #         "description": None,
    #         "tag": None,
    #         "is_default": None,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.create_configuration(**kwargs)

    # def test_create_rejects_empty_name_locally(self):
    #     """A missing name is caught before the call, mirroring Validate()."""
    #     result = self._create(name="")

    #     self.assertIn("error", result)
    #     self.assertIn("name", result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_create_rejects_overlong_name_locally(self):
    #     """The 2000-character name bound is enforced client-side."""
    #     result = self._create(name="x" * 2001)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_create_rejects_overlong_description_locally(self):
    #     """The 4000-character description bound is enforced client-side."""
    #     result = self._create(description="x" * 4001)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_create_rejects_unknown_platform_locally(self):
    #     """PlatformUnknown is rejected before the round trip."""
    #     result = self._create(platform="solaris")

    #     self.assertIn("error", result)
    #     self.assertIn("platform", result["error"])
    #     self.mock_client.command.assert_not_called()

    # # --- create_configuration: body construction ---

    # def test_create_omits_unset_optionals(self):
    #     """Unset optionals are pruned so the server keeps its own defaults.

    #     is_default is *bool in Go: nil and false are different. Sending false
    #     for an omitted argument would assert non-default on every create.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [_existing_config()]},
    #     }

    #     self._create()

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "PostConfigsV1")
    #     self.assertEqual(
    #         kwargs["body"],
    #         {
    #             "name": "Windows IR Triage",
    #             "platform": "windows",
    #             "collections": _WINDOWS_COLLECTIONS,
    #         },
    #     )

    # def test_create_sends_no_id_key(self):
    #     """Omitting `id` is the create signal; Go unmarshals absence to uuid.Nil."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [_existing_config()]},
    #     }

    #     self._create()

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertNotIn("id", kwargs["body"])

    # def test_create_sends_explicit_false_is_default(self):
    #     """An explicit False is forwarded, unlike an omitted value."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [_existing_config()]},
    #     }

    #     self._create(is_default=False)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertIs(kwargs["body"]["is_default"], False)

    # # --- create_configuration: response classification ---

    # def test_create_success_returns_configuration(self):
    #     """A populated 200 returns the stored configuration and the trace ID."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [_existing_config()],
    #             "meta": {"trace_id": "t-1"},
    #         },
    #     }

    #     result = self._create()

    #     self.assertEqual(result["configuration"]["id"], _CONFIG_ID)
    #     self.assertEqual(result["trace_id"], "t-1")

    # def test_create_duplicate_name_409(self):
    #     """A 409 says the name is taken and that nothing changed."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 409,
    #         "body": {
    #             "errors": [{"code": 409, "message": "duplicate configuration name"}]
    #         },
    #     }

    #     result = self._create()

    #     self.assertIn("error", result)
    #     self.assertIn("already exists", result["error"])

    # def test_create_400_carries_collector_validation_detail(self):
    #     """A rejected create keeps the per-collector errors, not just a failure.

    #     Server-side schema validation runs on save, so the 400 already holds the
    #     actionable detail. Collapsing it would force a redundant
    #     validate_configuration call to recover the same information.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 400,
    #         "body": {
    #             "errors": [
    #                 {
    #                     "code": 400,
    #                     "message": "unknown collector 'regstry'",
    #                     "type": "validation",
    #                 }
    #             ],
    #             "meta": {"trace_id": "t-2"},
    #         },
    #     }

    #     result = self._create()

    #     self.assertIn("error", result)
    #     self.assertIn("nothing was changed", result["error"])
    #     self.assertIs(result["details"]["valid"], False)
    #     self.assertIn("regstry", result["details"]["errors"][0]["message"])

    # def test_create_empty_200_is_ambiguous_not_success(self):
    #     """A 200 with no resource means the outcome is unknown.

    #     The handler's pre-defer return on an invalid user email writes no entity,
    #     so a bare 200 with an empty body is reachable. Reporting it as success
    #     would claim a configuration exists when it may not.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [], "errors": []},
    #     }

    #     result = self._create()

    #     self.assertIn("error", result)
    #     self.assertIn("unclear", result["error"])

    # # --- validate_configuration ---

    # def _validate(self, **overrides):
    #     kwargs = {
    #         "name": "Windows IR Triage",
    #         "platform": "windows",
    #         "collections": _WINDOWS_COLLECTIONS,
    #         "description": None,
    #         "tag": None,
    #         "is_default": None,
    #         "config_id": None,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.validate_configuration(**kwargs)

    # def test_validate_valid_configuration(self):
    #     """A clean 200 is a positive verdict, synthesised since the API sends no body."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [], "errors": [], "meta": {"trace_id": "t-3"}},
    #     }

    #     result = self._validate()

    #     self.assertIs(result["valid"], True)
    #     self.assertEqual(result["errors"], [])
    #     self.assertEqual(result["validated_by"], "server")

    # def test_validate_invalid_is_data_not_error(self):
    #     """A 400 is the verdict, so it must not look like a failed tool call.

    #     Routing this through the error path would discard the collector errors and
    #     tell the caller the tool broke, when in fact the check succeeded and found
    #     real problems.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 400,
    #         "body": {
    #             "errors": [
    #                 {
    #                     "code": 400,
    #                     "message": "collector 'registry': unknown option 'hive'",
    #                     "type": "validation",
    #                 }
    #             ],
    #             "meta": {"trace_id": "t-4"},
    #         },
    #     }

    #     result = self._validate()

    #     self.assertNotIn("error", result)
    #     self.assertIs(result["valid"], False)
    #     self.assertEqual(result["error_types"], ["validation"])
    #     self.assertIn("unknown option", result["errors"][0]["message"])

    # def test_validate_500_is_indeterminate_not_invalid(self):
    #     """A validator failure must not be reported as an invalid configuration.

    #     valid=False here would send the caller off rewriting collections that may
    #     be perfectly correct.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 500,
    #         "body": {
    #             "errors": [{"code": 500, "message": "error validating configuration"}]
    #         },
    #     }

    #     result = self._validate()

    #     self.assertIn("error", result)
    #     self.assertNotIn("valid", result)
    #     self.assertIn("neither accepted nor rejected", result["error"])

    # def test_validate_local_failure_flags_that_server_check_was_skipped(self):
    #     """The server short-circuits at Validate(), so collections went unchecked.

    #     Without the note, a caller sees valid=False and assumes the collections
    #     were examined.
    #     """
    #     result = self._validate(name="")

    #     self.assertIs(result["valid"], False)
    #     self.assertEqual(result["validated_by"], "client")
    #     self.assertIn("did NOT run", result["note"])
    #     self.mock_client.command.assert_not_called()

    # def test_validate_forwards_config_id_as_id(self):
    #     """Validating an edit sends the configuration's id."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"errors": []},
    #     }

    #     self._validate(config_id=_CONFIG_ID)

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "ValidateConfigurationV1")
    #     self.assertEqual(kwargs["body"]["id"], _CONFIG_ID)

    # # --- update_configuration ---

    # def _update(self, **overrides):
    #     kwargs = {
    #         "config_id": _CONFIG_ID,
    #         "name": None,
    #         "description": None,
    #         "collections": None,
    #         "platform": None,
    #         "tag": None,
    #         "is_default": None,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.update_configuration(**kwargs)

    # def test_update_requires_config_id(self):
    #     """No id means no read and no write."""
    #     result = self._update(config_id="")

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_update_reports_unknown_configuration(self):
    #     """A missing configuration is named in the error, with the lookup remedy."""
    #     with patch.object(self.module, "_base_get_by_ids", return_value=[]):
    #         result = self._update(name="New Name")

    #     self.assertIn("error", result)
    #     self.assertIn(_CONFIG_ID, result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_update_refuses_to_mutate_a_template(self):
    #     """Templates are the reference others clone; editing one in place is not the intent."""
    #     with patch.object(
    #         self.module,
    #         "_fetch_configuration",
    #         return_value=_existing_config(is_template=True),
    #     ):
    #         result = self._update(name="New Name")

    #     self.assertIn("error", result)
    #     self.assertIn("template", result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_update_preserves_omitted_fields(self):
    #     """Omitted arguments must be refilled from the stored configuration.

    #     SaveConfigRequest has no omitempty and the route is a full overwrite, so a
    #     body missing `description` nulls the stored value. This is the test that
    #     pins the PATCH-over-PUT behaviour.
    #     """
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 200,
    #             "body": {"resources": [_existing_config(name="Renamed")]},
    #         }

    #         self._update(name="Renamed")

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "PutConfigsV1")
    #     self.assertEqual(
    #         kwargs["body"],
    #         {
    #             "id": _CONFIG_ID,
    #             "name": "Renamed",
    #             "platform": "windows",
    #             "collections": _WINDOWS_COLLECTIONS,
    #             "description": "original description",
    #             "tag": "original-tag",
    #             "is_default": True,
    #         },
    #     )

    # def test_update_empty_string_clears_description(self):
    #     """An empty string is a real value and must reach the API, unlike None."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 200,
    #             "body": {"resources": [_existing_config()]},
    #         }

    #         self._update(description="")

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["description"], "")

    # def test_update_explicit_false_unsets_default(self):
    #     """is_default=False is forwarded rather than treated as omitted."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 200,
    #             "body": {"resources": [_existing_config()]},
    #         }

    #         self._update(is_default=False)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertIs(kwargs["body"]["is_default"], False)

    # def test_update_replaces_collections_wholesale(self):
    #     """A supplied collections array replaces the stored one entirely."""
    #     new_collections = [{"name": "Event Logs", "collector": "eventlog", "options": {}}]

    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 200,
    #             "body": {"resources": [_existing_config()]},
    #         }

    #         self._update(collections=new_collections)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["collections"], new_collections)

    # def test_update_blocks_platform_change_without_collections(self):
    #     """Switching platform while keeping old collections would carry invalid entries."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         result = self._update(platform="linux")

    #     self.assertIn("error", result)
    #     self.assertIn("without also supplying", result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_update_allows_platform_change_with_collections(self):
    #     """Supplying matching collections makes a platform change legitimate."""
    #     linux_collections = [{"name": "Syslog", "collector": "syslog", "options": {}}]

    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 200,
    #             "body": {"resources": [_existing_config(platform="linux")]},
    #         }

    #         self._update(platform="linux", collections=linux_collections)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["platform"], "linux")
    #     self.assertEqual(kwargs["body"]["collections"], linux_collections)

    # def test_update_validates_merged_result(self):
    #     """Validation runs on the merged document, not just the supplied arguments."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         result = self._update(name="x" * 2001)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_update_duplicate_name_409(self):
    #     """Renaming onto an existing name conflicts and changes nothing."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 409,
    #             "body": {
    #                 "errors": [{"code": 409, "message": "duplicate configuration name"}]
    #             },
    #         }

    #         result = self._update(name="Taken")

    #     self.assertIn("error", result)
    #     self.assertIn("already exists", result["error"])

    # def test_update_400_labels_the_operation(self):
    #     """The failure text says 'update', so the caller knows which call failed."""
    #     with patch.object(
    #         self.module, "_fetch_configuration", return_value=_existing_config()
    #     ):
    #         self.mock_client.command.return_value = {
    #             "status_code": 400,
    #             "body": {"errors": [{"code": 400, "message": "bad collector"}]},
    #         }

    #         result = self._update(collections=[{"name": "x", "collector": "?", "options": {}}])

    #     self.assertIn("update", result["error"])

    # # --- create_collection ---

    # def _create_collection(self, **overrides):
    #     kwargs = {
    #         "aids": [_AID_A],
    #         "ffcids": None,
    #         "config_id": _CONFIG_ID,
    #         "platform": None,
    #         "priority": 5,
    #         "deadline": None,
    #         "collection_tag": None,
    #         "self_destruct": None,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.create_collection(**kwargs)

    # def test_create_collection_requires_a_target(self):
    #     """No aids and no ffcids is refused locally."""
    #     result = self._create_collection(aids=None, ffcids=None)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_create_collection_enforces_combined_id_cap(self):
    #     """aids and ffcids are summed against the single maximum."""
    #     result = self._create_collection(
    #         aids=[_AID_A] * 3000, ffcids=[_AID_B] * 2001
    #     )

    #     self.assertIn("error", result)
    #     self.assertIn("5001", result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_create_collection_requires_platform_without_config_id(self):
    #     """Falling back to the default configuration needs an explicit platform."""
    #     result = self._create_collection(config_id=None, platform=None)

    #     self.assertIn("error", result)
    #     self.assertIn("platform", result["error"])
    #     self.mock_client.command.assert_not_called()

    # def test_create_collection_accepts_platform_without_config_id(self):
    #     """platform alone is sufficient when config_id is omitted."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "f1"}]},
    #     }

    #     self._create_collection(config_id=None, platform="windows")

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "PostCollectionsV1")
    #     self.assertEqual(kwargs["body"]["platform"], "windows")
    #     self.assertNotIn("config_id", kwargs["body"])

    # def test_create_collection_rejects_overlong_tag(self):
    #     """The collection tag length cap is enforced client-side."""
    #     result = self._create_collection(collection_tag="t" * 101)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_create_collection_always_sends_both_id_lists(self):
    #     """Both keys are present, empty rather than absent, for the unused list."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "f1"}]},
    #     }

    #     self._create_collection(aids=[_AID_A], ffcids=None)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["aids"], [_AID_A])
    #     self.assertEqual(kwargs["body"]["ffcids"], [])

    # def test_create_collection_omits_unset_optionals(self):
    #     """deadline, collection_tag and self_destruct are pruned when unset."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "f1"}]},
    #     }

    #     self._create_collection()

    #     _, kwargs = self.mock_client.command.call_args
    #     for key in ("deadline", "collection_tag", "self_destruct"):
    #         self.assertNotIn(key, kwargs["body"])

    # def test_create_collection_forwards_all_optionals(self):
    #     """Supplied scheduling options all reach the body."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"ffcid": "f1"}]},
    #     }

    #     self._create_collection(
    #         priority=9,
    #         deadline="2026-11-03T18:00:00Z",
    #         collection_tag="ir-case-42",
    #         self_destruct=True,
    #     )

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["priority"], 9)
    #     self.assertEqual(kwargs["body"]["deadline"], "2026-11-03T18:00:00Z")
    #     self.assertEqual(kwargs["body"]["collection_tag"], "ir-case-42")
    #     self.assertIs(kwargs["body"]["self_destruct"], True)

    # # --- deploy_collectors ---

    # def _deploy(self, **overrides):
    #     kwargs = {
    #         "aids": [_AID_A],
    #         "queue_offline": False,
    #         "no_proxy": False,
    #         "proxy_host": None,
    #         "proxy_port": None,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.deploy_collectors(**kwargs)

    # def test_deploy_requires_aids(self):
    #     """Unlike shutdown, deploy has no tenant-wide form."""
    #     result = self._deploy(aids=[])

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_deploy_enforces_aid_cap(self):
    #     """Oversized batches are rejected before the call."""
    #     result = self._deploy(aids=[_AID_A] * 10001)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_deploy_rejects_no_proxy_with_proxy_host(self):
    #     """no_proxy and a proxy host are mutually exclusive server-side."""
    #     result = self._deploy(no_proxy=True, proxy_host="p.corp", proxy_port=8080)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_deploy_rejects_host_without_port(self):
    #     """ProxyPort is seeded to -1, so a host with no port fails validation."""
    #     result = self._deploy(proxy_host="p.corp")

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_deploy_rejects_port_without_host(self):
    #     """A port with no host is the 'missing host' server error, caught locally."""
    #     result = self._deploy(proxy_port=8080)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_deploy_omits_proxy_keys_when_unset(self):
    #     """No proxy key may be sent when none was requested.

    #     The handler seeds ProxyPort to -1 as its 'unspecified' sentinel. Sending
    #     proxy_port=0 instead would trip the no_proxy conflict check, so a default
    #     of 0 would make no_proxy unusable.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}]},
    #     }

    #     self._deploy()

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "PostDeployV1")
    #     self.assertEqual(kwargs["body"], {"aids": [_AID_A], "queue_offline": False})

    # def test_deploy_sends_no_proxy_alone(self):
    #     """no_proxy travels without any host or port key."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}]},
    #     }

    #     self._deploy(no_proxy=True)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertIs(kwargs["body"]["no_proxy"], True)
    #     self.assertNotIn("proxy_host", kwargs["body"])
    #     self.assertNotIn("proxy_port", kwargs["body"])

    # def test_deploy_sends_proxy_pair(self):
    #     """A valid host and port pair is forwarded together."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}]},
    #     }

    #     self._deploy(proxy_host="p.corp", proxy_port=8080)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["proxy_host"], "p.corp")
    #     self.assertEqual(kwargs["body"]["proxy_port"], 8080)

    # def test_deploy_strips_whitespace_from_aids(self):
    #     """Padded AIDs would be unmarshalled as invalid UUIDs."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}]},
    #     }

    #     self._deploy(aids=[f"  {_AID_A}  "])

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["aids"], [_AID_A])

    # def test_deploy_full_success(self):
    #     """Every requested host deployed, so no warning is attached."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [{"aid": _AID_A}, {"aid": _AID_B}],
    #             "meta": {"trace_id": "t-5"},
    #         },
    #     }

    #     result = self._deploy(aids=[_AID_A, _AID_B])

    #     self.assertEqual(result["deployed_count"], 2)
    #     self.assertEqual(result["requested_count"], 2)
    #     self.assertNotIn("warning", result)

    # def test_deploy_partial_success_names_missing_hosts(self):
    #     """A 200 can cover fewer hosts than requested, with no entry in `errors`.

    #     Resources hold only what the service returned, so without this diff the
    #     caller would report success for hosts that were never touched.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}], "meta": {"trace_id": "t-6"}},
    #     }

    #     result = self._deploy(aids=[_AID_A, _AID_B])

    #     self.assertEqual(result["deployed_count"], 1)
    #     self.assertEqual(result["not_deployed"], [_AID_B])
    #     self.assertIn("warning", result)

    # def test_deploy_matches_aids_case_insensitively(self):
    #     """AID casing must not produce a false partial-failure report."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A.upper()}]},
    #     }

    #     result = self._deploy(aids=[_AID_A])

    #     self.assertEqual(result["deployed_count"], 1)
    #     self.assertNotIn("not_deployed", result)

    # def test_deploy_failure_states_nothing_deployed(self):
    #     """A 400 with no resources must say explicitly that nothing happened."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 400,
    #         "body": {
    #             "errors": [{"code": 400, "message": "no valid aids"}],
    #             "resources": [],
    #         },
    #     }

    #     result = self._deploy()

    #     self.assertIn("error", result)
    #     self.assertIn("No collectors were deployed", result["error"])

    # # --- shutdown_collectors ---

    # def _shutdown(self, **overrides):
    #     kwargs = {
    #         "aids": [_AID_A],
    #         "ffcids": None,
    #         "platform": None,
    #         "self_destruct": False,
    #         "force": False,
    #     }
    #     kwargs.update(overrides)
    #     return self.module.shutdown_collectors(**kwargs)

    # def test_shutdown_refuses_empty_target_list(self):
    #     """An empty request is a tenant-wide shutdown and must be refused.

    #     The server's own len(AIDs)+len(FfcAIDs)==0 guard is commented out, so an
    #     argument-free call terminates every collector in the CID — the single
    #     easiest call for a caller to emit by accident.
    #     """
    #     result = self._shutdown(aids=None, ffcids=None)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_shutdown_enforces_combined_cap(self):
    #     """aids and ffcids are summed against one maximum."""
    #     result = self._shutdown(aids=[_AID_A] * 6000, ffcids=[_AID_B] * 4001)

    #     self.assertIn("error", result)
    #     self.mock_client.command.assert_not_called()

    # def test_shutdown_sends_both_id_lists_and_flags(self):
    #     """self_destruct and force have no omitempty, so they are always sent."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A, "ffcid": "f1"}]},
    #     }

    #     self._shutdown()

    #     args, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(args[0], "ShutdownCollectorsV1")
    #     self.assertEqual(
    #         kwargs["body"],
    #         {
    #             "aids": [_AID_A],
    #             "ffcids": [],
    #             "self_destruct": False,
    #             "force": False,
    #         },
    #     )

    # def test_shutdown_omits_platform_when_unset(self):
    #     """Platform is seeded to PlatformUnknown, so the key is left out."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": []},
    #     }

    #     self._shutdown()

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertNotIn("platform", kwargs["body"])

    # def test_shutdown_forwards_platform_and_flags(self):
    #     """Explicit platform, self_destruct and force all reach the body."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A}]},
    #     }

    #     self._shutdown(platform="windows", self_destruct=True, force=True)

    #     _, kwargs = self.mock_client.command.call_args
    #     self.assertEqual(kwargs["body"]["platform"], "windows")
    #     self.assertIs(kwargs["body"]["self_destruct"], True)
    #     self.assertIs(kwargs["body"]["force"], True)

    # def test_shutdown_success_echoes_self_destruct(self):
    #     """The result records whether collectors were uninstalled, not just stopped."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {
    #             "resources": [{"aid": _AID_A, "ffcid": "f1"}],
    #             "meta": {"trace_id": "t-7"},
    #         },
    #     }

    #     result = self._shutdown(self_destruct=True)

    #     self.assertEqual(result["shutdown_count"], 1)
    #     self.assertIs(result["self_destruct"], True)

    # def test_shutdown_matches_targets_on_aid_or_ffcid(self):
    #     """Targets may be given as either identifier, so both are checked."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A, "ffcid": "f1"}]},
    #     }

    #     result = self._shutdown(aids=[_AID_A], ffcids=["f1"])

    #     self.assertNotIn("not_shutdown", result)

    # def test_shutdown_partial_names_unmatched_targets(self):
    #     """Requested targets with no returned collector are reported back."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 200,
    #         "body": {"resources": [{"aid": _AID_A, "ffcid": "f1"}]},
    #     }

    #     result = self._shutdown(aids=[_AID_A, _AID_B])

    #     self.assertEqual(result["not_shutdown"], [_AID_B])
    #     self.assertIn("warning", result)

    # def test_shutdown_404_is_benign_and_discourages_force_retry(self):
    #     """Nothing running is not a failure, and force is the wrong response.

    #     ErrNoInProgressCollector means no state changed. Surfacing it as an error
    #     invites a retry with force=true, which risks abandoning a collection
    #     elsewhere while fixing nothing here.
    #     """
    #     self.mock_client.command.return_value = {
    #         "status_code": 404,
    #         "body": {
    #             "errors": [{"code": 404, "message": "no in progress collector"}],
    #             "meta": {"trace_id": "t-8"},
    #         },
    #     }

    #     result = self._shutdown()

    #     self.assertNotIn("error", result)
    #     self.assertIs(result["no_collectors_in_progress"], True)
    #     self.assertEqual(result["shutdown_count"], 0)
    #     self.assertIn("force=true", result["message"])

    # def test_shutdown_500_is_an_error(self):
    #     """An internal failure stays an error, unlike the 404 case."""
    #     self.mock_client.command.return_value = {
    #         "status_code": 500,
    #         "body": {"errors": [{"code": 500, "message": "internal"}], "resources": []},
    #     }

    #     result = self._shutdown()

    #     self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
