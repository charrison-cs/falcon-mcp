"""
Tests for the Forensics module.
"""

import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.forensics import (
    ForensicsModule,
    _MAX_CANCEL_COLLECTION_IDS,
    _MAX_COLLECTION_IDS,
    _MAX_COLLECTION_TAG_LENGTH,
    _MAX_DEPLOY_OR_SHUTDOWN_AIDS,
)
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
_FFCID_A = "aaaabbbbccccddddaaaabbbbccccdddd"
_CONFIG_ID = "11111111-2222-3333-4444-555555555555"
_COLLECTION_ID_A = "99998888777766665555444433332222"
_COLLECTION_ID_B = "11112222333344445555666677778888"

_WINDOWS_COLLECTIONS = [
    {"name": "Registry Hives", "collector": "registry", "options": {"hives": ["SYSTEM"]}}
]
_LINUX_COLLECTIONS = [
    {"name": "Bash History", "collector": "file", "options": {"paths": ["/root/.bash_history"]}}
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


def _ok(resources, errors=None, trace_id="trace-1"):
    """A 200 StructuredResponseV1."""
    return {
        "status_code": 200,
        "body": {
            "resources": resources,
            "errors": errors or [],
            "meta": {"trace_id": trace_id},
        },
    }


def _err(status, messages, resources=None, trace_id="trace-1"):
    """A non-200 StructuredResponseV1."""
    return {
        "status_code": status,
        "body": {
            "resources": resources or [],
            "errors": [{"code": status, "message": m} for m in messages],
            "meta": {"trace_id": trace_id},
        },
    }


class ForensicsTestCase(TestModules):
    """Shared fixtures and explicit-argument call helpers.

    Pydantic ``Field`` defaults do not resolve on a direct method call, so every
    helper passes every parameter. This mirrors ``_execute`` in the Fusion tests.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(ForensicsModule)

    # --- assertion helpers ---

    def assert_is_error(self, result):
        """Assert an error payload, tolerating a list-wrapped dict.

        The base-class helpers return a bare error dict, but some callers wrap
        it to satisfy a declared ``list[dict]`` return type, so unwrap a
        single-element list before checking.
        """
        payload = result[0] if isinstance(result, list) and len(result) == 1 else result
        self.assertIsInstance(payload, dict)
        self.assertIn("error", payload)
        return payload

    def called_operation(self, index=0):
        """Operation name from the nth client.command call."""
        args, _ = self.mock_client.command.call_args_list[index]
        return args[0]

    def called_kwargs(self, index=0):
        """Keyword arguments from the nth client.command call."""
        _, kwargs = self.mock_client.command.call_args_list[index]
        return kwargs

    # --- call helpers ---

    def search_collections(self, **overrides):
        kwargs = {
            "ids": None,
            "filter": None,
            "limit": 10,
            "offset": None,
            "sort": "modified_timestamp.desc",
        }
        kwargs.update(overrides)
        return self.module.search_collections(**kwargs)

    def search_collectors(self, **overrides):
        kwargs = {
            "ids": None,
            "filter": None,
            "limit": 10,
            "offset": None,
            "sort": "seen_timestamp.desc",
        }
        kwargs.update(overrides)
        return self.module.search_collectors(**kwargs)

    def search_configs(self, **overrides):
        kwargs = {
            "filter": None,
            "limit": 10,
            "offset": None,
            "sort": "modified_timestamp.desc",
        }
        kwargs.update(overrides)
        return self.module.search_configurations_and_templates(**kwargs)

    def validate_configuration(self, **overrides):
        kwargs = {
            "name": "Cloned Windows Triage",
            "platform": "windows",
            "collections": _WINDOWS_COLLECTIONS,
            "description": None,
            "tag": None,
            "is_default": None,
            "config_id": None,
        }
        kwargs.update(overrides)
        return self.module.validate_configuration(**kwargs)

    def create_configuration(self, **overrides):
        kwargs = {
            "name": "Cloned Windows Triage",
            "platform": "windows",
            "collections": _WINDOWS_COLLECTIONS,
            "description": None,
            "tag": None,
            "is_default": None,
        }
        kwargs.update(overrides)
        return self.module.create_configuration(**kwargs)

    def update_configuration(self, **overrides):
        kwargs = {
            "config_id": _CONFIG_ID,
            "name": None,
            "description": None,
            "collections": None,
            "platform": None,
            "tag": None,
            "is_default": None,
        }
        kwargs.update(overrides)
        return self.module.update_configuration(**kwargs)

    def create_collection(self, **overrides):
        kwargs = {
            "aids": [_AID_A],
            "ffcids": None,
            "config_id": _CONFIG_ID,
            "platform": None,
            "priority": 5,
            "deadline": None,
            "collection_tag": None,
            "self_destruct": None,
        }
        kwargs.update(overrides)
        return self.module.create_collection(**kwargs)

    def cancel_collections(self, **overrides):
        kwargs = {"ids": [_COLLECTION_ID_A]}
        kwargs.update(overrides)
        return self.module.cancel_collections(**kwargs)

    def deploy_collectors(self, **overrides):
        kwargs = {
            "aids": [_AID_A],
            "queue_offline": False,
            "no_proxy": False,
            "proxy_host": None,
            "proxy_port": None,
        }
        kwargs.update(overrides)
        return self.module.deploy_collectors(**kwargs)

    def shutdown_collectors(self, **overrides):
        kwargs = {
            "aids": [_AID_A],
            "ffcids": None,
            "self_destruct": False,
            "force": False,
        }
        kwargs.update(overrides)
        return self.module.shutdown_collectors(**kwargs)


class TestForensicsRegistration(ForensicsTestCase):
    """Tool and resource registration, and annotation correctness."""

    def test_register_tools(self):
        """All forensics tools register under the falcon_ prefix."""
        expected_tools = [
            "falcon_search_collections",
            "falcon_search_collectors",
            "falcon_search_configurations_and_templates",
            "falcon_validate_configuration",
            "falcon_create_configuration",
            "falcon_update_configuration",
            "falcon_create_collection",
            "falcon_cancel_collections",
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
            "falcon_search_configurations_and_templates",
            "falcon_validate_configuration",
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)

    def test_mutating_tools_declare_their_blast_radius(self):
        """Each write tool carries annotations matching what it actually does.

        These hints drive client-side confirmation prompts, so a tool that
        touches live endpoints must not advertise itself as safe. Creates are
        non-destructive but non-idempotent (a second call starts a second run);
        cancel and shutdown are destructive and idempotent (repeating finds
        nothing left to stop); deploy is destructive and non-idempotent.
        """
        self.module.register_tools(self.mock_server)
        expected = {
            "falcon_create_configuration": _CREATE_ANNOTATIONS,
            "falcon_create_collection": _CREATE_ANNOTATIONS,
            "falcon_update_configuration": _DESTRUCTIVE_IDEMPOTENT,
            "falcon_cancel_collections": _DESTRUCTIVE_IDEMPOTENT,
            "falcon_shutdown_collectors": _DESTRUCTIVE_IDEMPOTENT,
            "falcon_deploy_collectors": _DESTRUCTIVE_NON_IDEMPOTENT,
        }
        for name, annotations in expected.items():
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, annotations)


class TestSearchCollections(ForensicsTestCase):
    """search_collections."""

    def test_success_returns_pagination_envelope(self):
        """Full records come back inside the envelope with filter_used echoed."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": _COLLECTION_ID_A, "state": "complete", "platform": "windows"},
                    {"id": _COLLECTION_ID_B, "state": "in progress", "platform": "windows"},
                ],
                "meta": {"pagination": {"offset": 0, "limit": 10, "total": 2}},
            },
        }

        result = self.search_collections(filter="platform:'windows'")

        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], _COLLECTION_ID_A)
        self.assertEqual(result["filter_used"], "platform:'windows'")
        self.assert_pagination(result, total=2)

        # One call: the combined endpoint returns full records, so there is no
        # hydrate-by-ID second step.
        self.mock_client.command.assert_called_once()
        self.assertEqual(self.called_operation(), "GetCombinedCollectionsV1")
        self.assertEqual(
            self.called_kwargs()["parameters"],
            {
                "filter": "platform:'windows'",
                "limit": 10,
                "sort": "modified_timestamp.desc",
            },
        )

    def test_forwards_ids_and_offset(self):
        """ids and offset reach the API when supplied.

        `ids` is this tool's only route to a specific collection now that the
        dedicated by-ID tools are gone, so it must not be dropped.
        """
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        self.search_collections(
            ids=[_COLLECTION_ID_A], offset=50, limit=25, sort="priority.desc"
        )

        self.assertEqual(
            self.called_kwargs()["parameters"],
            {
                "ids": [_COLLECTION_ID_A],
                "limit": 25,
                "offset": 50,
                "sort": "priority.desc",
            },
        )

    def test_empty_result_still_returns_envelope(self):
        """No matches is a successful search, not an error."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"offset": 0, "limit": 10, "total": 0}},
            },
        }

        result = self.search_collections(filter="state:'complete'")

        self.assertEqual(result["results"], [])
        self.assertNotIn("error", result)
        self.assert_pagination(result, total=0)

    def test_bad_filter_surfaces_api_message(self):
        """A 400 keeps the API's field-level message so a retry can be correct."""
        self.mock_client.command.return_value = _err(
            400, ["Invalid FQL: fql: bogus is an unknown property"]
        )

        result = self.search_collections(filter="bogus:'x'")

        self.assertIn("error", result)
        self.assertIn("unknown property", result["error"])

    def test_scope_error_surfaces_details(self):
        """A 403 surfaces as an error with details, not an empty envelope."""
        self.mock_client.command.return_value = _err(
            403, ["access denied, authorization failed"]
        )

        result = self.search_collections()

        self.assertIn("error", result)
        self.assertIn("details", result)
        self.assertNotIn("results", result)


class TestSearchCollectors(ForensicsTestCase):
    """search_collectors."""

    def test_success_returns_pagination_envelope(self):
        """Collector records come back inside the envelope."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{"ffcid": _FFCID_A, "aid": _AID_A, "state": "online"}],
                "meta": {"pagination": {"offset": 0, "limit": 10, "total": 1}},
            },
        }

        result = self.search_collectors(filter="state:'online'")

        self.assertEqual(result["results"][0]["ffcid"], _FFCID_A)
        self.assertEqual(result["filter_used"], "state:'online'")
        self.assert_pagination(result, total=1)
        self.assertEqual(self.called_operation(), "GetCombinedCollectorsV1")
        self.assertEqual(
            self.called_kwargs()["parameters"],
            {"filter": "state:'online'", "limit": 10, "sort": "seen_timestamp.desc"},
        )

    def test_forwards_ids_and_offset(self):
        """ids and offset reach the API when supplied."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        self.search_collectors(ids=[_FFCID_A], offset=20, limit=50, sort="platform.asc")

        self.assertEqual(
            self.called_kwargs()["parameters"],
            {
                "ids": [_FFCID_A],
                "limit": 50,
                "offset": 20,
                "sort": "platform.asc",
            },
        )

    def test_error_surfaces_api_message(self):
        """A 500 surfaces as an error dict, not an envelope."""
        self.mock_client.command.return_value = _err(500, ["Internal Server Error"])

        result = self.search_collectors()

        self.assertIn("error", result)
        self.assertNotIn("results", result)


class TestSearchConfigurations(ForensicsTestCase):
    """search_configurations_and_templates."""

    def test_success_returns_templates_and_configs(self):
        """Templates and configurations share one envelope, flagged by is_template."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "t1", "name": "Windows Template", "is_template": True},
                    {"id": _CONFIG_ID, "name": "Windows IR Triage", "is_template": False},
                ],
                "meta": {"pagination": {"offset": 0, "limit": 10, "total": 2}},
            },
        }

        result = self.search_configs(filter="platform:'windows'")

        self.assertTrue(result["results"][0]["is_template"])
        self.assertEqual(result["filter_used"], "platform:'windows'")
        self.assert_pagination(result, total=2)
        self.assertEqual(self.called_operation(), "GetCombinedConfigsAndTemplatesV1")
        self.assertEqual(
            self.called_kwargs()["parameters"],
            {
                "filter": "platform:'windows'",
                "limit": 10,
                "sort": "modified_timestamp.desc",
            },
        )

    def test_forwards_offset(self):
        """offset reaches the API when supplied."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        self.search_configs(offset=30, limit=25, sort="name.asc")

        self.assertEqual(
            self.called_kwargs()["parameters"],
            {"limit": 25, "offset": 30, "sort": "name.asc"},
        )

    def test_error_surfaces_api_message(self):
        """A 400 surfaces as an error dict."""
        self.mock_client.command.return_value = _err(400, ["invalid sort 'bogus'"])

        result = self.search_configs(sort="bogus.desc")

        self.assertIn("error", result)
        self.assertIn("invalid sort", result["error"])


class TestValidateConfiguration(ForensicsTestCase):
    """validate_configuration and the verdict classifier."""

    def test_valid_configuration(self):
        """A clean 200 is an explicit positive verdict, attributed to the server."""
        self.mock_client.command.return_value = _ok([], trace_id="tr-valid")

        result = self.validate_configuration()

        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["validated_by"], "server")
        self.assertEqual(result["trace_id"], "tr-valid")
        self.assertEqual(self.called_operation(), "ValidateConfigV1")

    def test_invalid_configuration_preserves_collector_errors(self):
        """A 400 is a verdict, not a tool failure, and errors pass through verbatim.

        The error objects carry the offending collector name and field path,
        which is the only actionable detail a caller has for fixing the
        untyped `options` payload, so they must not be reformatted.
        """
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {
                "errors": [
                    {
                        "code": 400,
                        "type": "validation",
                        "message": "collector 'registry': unknown option 'hive'",
                    },
                    {"code": 400, "type": "platform", "message": "not valid on windows"},
                ],
                "meta": {"trace_id": "tr-invalid"},
            },
        }

        result = self.validate_configuration()

        self.assertFalse(result["valid"])
        self.assertNotIn("error", result)
        self.assertEqual(len(result["errors"]), 2)
        self.assertIn("unknown option 'hive'", result["errors"][0]["message"])
        self.assertEqual(result["error_types"], ["platform", "validation"])
        self.assertEqual(result["validated_by"], "server")

    def test_invalid_configuration_tolerates_untyped_errors(self):
        """Errors with no `type` are kept but contribute no error_types entry."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"code": 400, "message": "bad collections"}], "meta": {}},
        }

        result = self.validate_configuration()

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_types"], [])

    def test_validator_failure_is_not_a_negative_verdict(self):
        """A 500 means no verdict was produced; reporting invalid would mislead.

        The validator itself failing says nothing about the configuration, and a
        false `valid: false` would send the caller off rewriting collections
        that may be correct.
        """
        self.mock_client.command.return_value = _err(500, ["validation failed"])

        result = self.validate_configuration()

        self.assertIn("error", result)
        self.assertNotIn("valid", result)
        self.assertIn("neither accepted nor rejected", result["error"])

    def test_local_rejection_reports_that_server_check_did_not_run(self):
        """A locally-rejected request must not look like a collector verdict.

        Returning a bare `valid: false` here would imply the collections were
        examined, so the response is attributed to the client and says the
        server check was skipped.
        """
        result = self.validate_configuration(name="")

        self.assertFalse(result["valid"])
        self.assertEqual(result["validated_by"], "client")
        self.assertEqual(result["error_types"], ["request"])
        self.assertIn("did NOT run", result["note"])
        self.mock_client.command.assert_not_called()

    def test_local_rejection_on_oversized_name(self):
        """A name over the limit is caught locally."""
        result = self.validate_configuration(name="x" * 2001)

        self.assertFalse(result["valid"])
        self.mock_client.command.assert_not_called()

    def test_local_rejection_on_oversized_description(self):
        """A description over the limit is caught locally."""
        result = self.validate_configuration(description="d" * 4001)

        self.assertFalse(result["valid"])
        self.mock_client.command.assert_not_called()

    def test_local_rejection_on_unknown_platform(self):
        """An unsupported platform is caught locally."""
        result = self.validate_configuration(platform="solaris")

        self.assertFalse(result["valid"])
        self.mock_client.command.assert_not_called()

    def test_body_omits_unset_optionals_and_maps_config_id_to_id(self):
        """Only supplied fields are sent, and config_id travels as `id`."""
        self.mock_client.command.return_value = _ok([])

        self.validate_configuration(
            description="desc", tag="ir", is_default=True, config_id=_CONFIG_ID
        )

        self.assertEqual(
            self.called_kwargs()["body"],
            {
                "name": "Cloned Windows Triage",
                "platform": "windows",
                "collections": _WINDOWS_COLLECTIONS,
                "id": _CONFIG_ID,
                "description": "desc",
                "tag": "ir",
                "is_default": True,
            },
        )

    def test_body_for_new_configuration_has_no_id(self):
        """Validating a new configuration must not send an `id`."""
        self.mock_client.command.return_value = _ok([])

        self.validate_configuration()

        self.assertNotIn("id", self.called_kwargs()["body"])


class TestCreateConfiguration(ForensicsTestCase):
    """create_configuration."""

    def test_success_calls_the_create_operation(self):
        """The create path must persist, not merely validate.

        This previously called ValidateConfigV1 — the same operation as
        validate_configuration — so a tool annotated as a write reported a
        created configuration while storing nothing. Pinning the operation
        keeps the two paths from collapsing back together.
        """
        self.mock_client.command.return_value = _ok([_existing_config()])

        self.create_configuration()

        self.assertEqual(self.called_operation(), "PostConfigsV1")

    def test_success_returns_the_stored_configuration(self):
        """The created record is returned under `configuration` with its trace id."""
        stored = _existing_config(name="Cloned Windows Triage")
        self.mock_client.command.return_value = _ok([stored], trace_id="tr-create")

        result = self.create_configuration()

        self.assertEqual(result["configuration"]["id"], _CONFIG_ID)
        self.assertEqual(result["trace_id"], "tr-create")

    def test_local_validation_blocks_the_write(self):
        """A bad request is rejected before any write is attempted."""
        result = self.create_configuration(name="")

        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_duplicate_name_is_reported_as_no_change(self):
        """A 409 must state that nothing changed, so no cleanup is attempted."""
        self.mock_client.command.return_value = _err(409, ["name already exists"])

        result = self.create_configuration()

        self.assertIn("error", result)
        self.assertIn("already exists", result["error"])
        self.assertIn("Nothing was changed", result["error"])

    def test_validation_rejection_nests_the_collector_errors(self):
        """A 400 keeps the per-collector detail needed to fix the collections."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {
                "errors": [
                    {
                        "code": 400,
                        "type": "validation",
                        "message": "collector 'registry': unknown option 'hive'",
                    }
                ],
                "meta": {"trace_id": "tr-400"},
            },
        }

        result = self.create_configuration()

        self.assertIn("error", result)
        self.assertIn("rejected by validation", result["error"])
        self.assertFalse(result["details"]["valid"])
        self.assertIn("unknown option 'hive'", result["details"]["errors"][0]["message"])

    def test_success_without_a_resource_is_treated_as_uncertain(self):
        """A 200 with no record leaves the outcome unknown, so say so.

        Reporting success here would have the caller believe a configuration
        exists that it cannot reference; reporting plain failure would invite a
        retry that could duplicate it. Both are wrong, so the response asks for
        a re-read instead.
        """
        self.mock_client.command.return_value = _ok([], trace_id="tr-empty")

        result = self.create_configuration()

        self.assertIn("error", result)
        self.assertIn("unclear whether the change was applied", result["error"])
        self.assertEqual(result["details"]["trace_id"], "tr-empty")

    def test_server_error_surfaces_status_and_trace(self):
        """A 500 reports the status and keeps the trace id for support."""
        self.mock_client.command.return_value = _err(
            500, ["failed to save config"], trace_id="tr-500"
        )

        result = self.create_configuration()

        self.assertIn("HTTP 500", result["error"])
        self.assertEqual(result["details"]["trace_id"], "tr-500")

    def test_body_includes_only_supplied_optionals(self):
        """Unset optionals are omitted so defaults are not silently overwritten."""
        self.mock_client.command.return_value = _ok([_existing_config()])

        self.create_configuration(description="d", tag="t", is_default=False)

        self.assertEqual(self.called_operation(), "PostConfigsV1")
        body = self.called_kwargs()["body"]
        self.assertEqual(body["name"], "Cloned Windows Triage")
        self.assertEqual(body["platform"], "windows")
        self.assertEqual(body["collections"], _WINDOWS_COLLECTIONS)
        self.assertEqual(body["description"], "d")
        self.assertEqual(body["tag"], "t")
        self.assertIs(body["is_default"], False)
        self.assertNotIn("id", body)


class TestUpdateConfiguration(ForensicsTestCase):
    """update_configuration: read-modify-write merging."""

    def _read_then_write(self, existing=None, write=None):
        """Queue the by-ID read followed by the write."""
        self.mock_client.command.side_effect = [
            _ok([existing or _existing_config()]),
            write or _ok([_existing_config(name="Renamed")], trace_id="tr-update"),
        ]

    def test_omitted_fields_are_carried_over_from_the_existing_record(self):
        """The API is a full overwrite, so omission must mean "keep", not "clear".

        Sending only the changed field would blank everything else, so this
        pins that every untouched value is read back and resent.
        """
        self._read_then_write()

        result = self.update_configuration(name="Renamed")

        self.assertEqual(result["configuration"]["name"], "Renamed")
        self.assertEqual(self.called_operation(1), "PutConfigsV1")
        self.assertEqual(
            self.called_kwargs(1)["body"],
            {
                "name": "Renamed",
                "platform": "windows",
                "collections": _WINDOWS_COLLECTIONS,
                "id": _CONFIG_ID,
                "description": "original description",
                "tag": "original-tag",
                "is_default": True,
            },
        )

    def test_collections_are_replaced_wholesale(self):
        """A supplied collections array replaces, never merges with, the stored one."""
        replacement = _WINDOWS_COLLECTIONS + [
            {"name": "Event Logs", "collector": "evtx", "options": {}}
        ]
        self._read_then_write()

        self.update_configuration(collections=replacement)

        self.assertEqual(self.called_kwargs(1)["body"]["collections"], replacement)

    def test_empty_string_clears_description(self):
        """"" is a value, distinct from omission, so it reaches the API."""
        self._read_then_write()

        self.update_configuration(description="")

        self.assertEqual(self.called_kwargs(1)["body"]["description"], "")

    def test_empty_string_clears_tag(self):
        """"" clears the tag rather than keeping the existing one."""
        self._read_then_write()

        self.update_configuration(tag="")

        self.assertEqual(self.called_kwargs(1)["body"]["tag"], "")

    def test_is_default_false_is_honored(self):
        """False is a real value and must not be mistaken for "unset".

        A truthiness check instead of an `is not None` check would silently
        re-send the stored True and leave the configuration as the default.
        """
        self._read_then_write(existing=_existing_config(is_default=True))

        self.update_configuration(is_default=False)

        self.assertIs(self.called_kwargs(1)["body"]["is_default"], False)

    def test_missing_config_id_makes_no_api_call(self):
        """A blank id is rejected locally; the read is not attempted."""
        result = self.update_configuration(config_id="")

        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_unknown_config_id_does_not_attempt_a_write(self):
        """If the read finds nothing, no write is issued with invented values."""
        self.mock_client.command.return_value = _ok([])

        result = self.update_configuration(name="Renamed")

        self.assertIn("error", result)
        self.assertIn("No configuration found", result["error"])
        self.mock_client.command.assert_called_once()

    def test_read_error_is_propagated_without_writing(self):
        """A failed read aborts; writing after it would overwrite blind."""
        self.mock_client.command.return_value = _err(403, ["access denied"])

        self.assert_is_error(self.update_configuration(name="Renamed"))

        self.mock_client.command.assert_called_once()

    def test_templates_are_refused(self):
        """Templates are shared reference material, so editing in place is refused.

        The model guide tells callers to clone a template's collections; an
        agent following that advice can easily target the template's own id.
        Rewriting it would corrupt the source everyone else clones from, and
        that damage is invisible until someone else's clone comes out wrong.
        """
        self.mock_client.command.return_value = _ok([_existing_config(is_template=True)])

        result = self.update_configuration(name="Renamed")

        self.assertIn("error", result)
        self.assertIn("is a template", result["error"])
        self.assertIn("create_configuration", result["error"])
        self.mock_client.command.assert_called_once()

    def test_platform_change_without_collections_is_refused(self):
        """Collections are platform-specific, so the old ones cannot be carried over.

        Letting this through would send windows collectors to a linux
        configuration and fail server-side, or worse, persist a configuration
        that collects nothing.
        """
        self.mock_client.command.return_value = _ok([_existing_config()])

        result = self.update_configuration(platform="linux")

        self.assertIn("error", result)
        self.assertIn("without also supplying `collections`", result["error"])
        self.mock_client.command.assert_called_once()

    def test_platform_change_with_collections_is_allowed(self):
        """Supplying matching collections makes a platform change legitimate."""
        self._read_then_write()

        self.update_configuration(platform="linux", collections=_LINUX_COLLECTIONS)

        body = self.called_kwargs(1)["body"]
        self.assertEqual(body["platform"], "linux")
        self.assertEqual(body["collections"], _LINUX_COLLECTIONS)

    def test_same_platform_restated_without_collections_is_allowed(self):
        """Restating the current platform is a no-op, not a platform change."""
        self._read_then_write()

        self.update_configuration(platform="windows")

        self.assertEqual(self.called_kwargs(1)["body"]["platform"], "windows")

    def test_merged_values_are_revalidated(self):
        """Validation runs on the merged document, not just the supplied fields."""
        self.mock_client.command.return_value = _ok([_existing_config()])

        result = self.update_configuration(name="x" * 2001)

        self.assertIn("error", result)
        self.mock_client.command.assert_called_once()

    def test_duplicate_name_conflict_reports_no_change(self):
        """A 409 on rename states nothing changed."""
        self._read_then_write(write=_err(409, ["name already exists"]))

        result = self.update_configuration(name="Windows Template")

        self.assertIn("already exists", result["error"])
        self.assertIn("Nothing was changed", result["error"])


class TestCreateCollection(ForensicsTestCase):
    """create_collection."""

    def test_success_sends_the_expected_body(self):
        """Targets and scheduling options are sent; unset optionals are omitted."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.create_collection(
            aids=[_AID_A, _AID_B],
            ffcids=[_FFCID_A],
            collection_tag="ir-2026-10",
            deadline="2026-11-03T18:00:00Z",
            priority=9,
            self_destruct=True,
        )

        self.assertEqual(self.called_operation(), "PostCollectionsV1")
        self.assertEqual(
            self.called_kwargs()["body"],
            {
                "aids": [_AID_A, _AID_B],
                "ffcids": [_FFCID_A],
                "config_id": _CONFIG_ID,
                "priority": 9,
                "deadline": "2026-11-03T18:00:00Z",
                "collection_tag": "ir-2026-10",
                "self_destruct": True,
            },
        )

    def test_absent_target_lists_are_sent_as_empty_arrays(self):
        """Omitted aids/ffcids become [] rather than null."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.create_collection(aids=None, ffcids=[_FFCID_A])

        body = self.called_kwargs()["body"]
        self.assertEqual(body["aids"], [])
        self.assertEqual(body["ffcids"], [_FFCID_A])

    def test_no_targets_makes_no_api_call(self):
        """A run with no hosts is rejected locally."""
        result = self.create_collection(aids=None, ffcids=None)

        self.assertIn("error", result)
        self.assertIn("At least one agent ID", result["error"])
        self.mock_client.command.assert_not_called()

    def test_empty_target_lists_make_no_api_call(self):
        """Two empty lists are still no hosts."""
        result = self.create_collection(aids=[], ffcids=[])

        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_target_count_is_capped_across_both_lists(self):
        """The cap applies to aids + ffcids combined, not each list separately."""
        half = _MAX_COLLECTION_IDS // 2 + 1
        result = self.create_collection(aids=[_AID_A] * half, ffcids=[_FFCID_A] * half)

        self.assertIn("error", result)
        self.assertIn(str(_MAX_COLLECTION_IDS), result["error"])
        self.mock_client.command.assert_not_called()

    def test_at_the_target_cap_is_allowed(self):
        """Exactly the maximum is accepted; the check is inclusive."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.create_collection(aids=[_AID_A] * _MAX_COLLECTION_IDS)

        self.mock_client.command.assert_called_once()

    def test_platform_is_required_without_a_config_id(self):
        """Falling back to the platform default needs a platform to pick it."""
        result = self.create_collection(config_id=None, platform=None)

        self.assertIn("error", result)
        self.assertIn("`platform` is required", result["error"])
        self.mock_client.command.assert_not_called()

    def test_platform_alone_selects_the_default_configuration(self):
        """With no config_id, platform is sent so the server picks the default."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.create_collection(config_id=None, platform="linux")

        body = self.called_kwargs()["body"]
        self.assertEqual(body["platform"], "linux")
        self.assertNotIn("config_id", body)

    def test_oversized_collection_tag_makes_no_api_call(self):
        """A tag over the limit is caught locally."""
        result = self.create_collection(
            collection_tag="t" * (_MAX_COLLECTION_TAG_LENGTH + 1)
        )

        self.assertIn("error", result)
        self.assertIn(str(_MAX_COLLECTION_TAG_LENGTH), result["error"])
        self.mock_client.command.assert_not_called()

    def test_api_error_is_surfaced(self):
        """A rejected run surfaces the API message."""
        self.mock_client.command.return_value = _err(400, ["no valid AIDs"])

        self.assert_is_error(self.create_collection())


class TestCancelCollections(ForensicsTestCase):
    """cancel_collections."""

    def test_success_reports_counts_and_records(self):
        """Cancelled records and both counts come back for comparison."""
        self.mock_client.command.return_value = _ok(
            [{"id": _COLLECTION_ID_A, "state": "cancelling"}], trace_id="tr-cancel"
        )

        result = self.cancel_collections(ids=[_COLLECTION_ID_A])

        self.assertEqual(result["cancelled_count"], 1)
        self.assertEqual(result["requested_count"], 1)
        self.assertEqual(result["collections"][0]["state"], "cancelling")
        self.assertEqual(result["trace_id"], "tr-cancel")
        self.assertNotIn("not_cancelled", result)

    def test_ids_travel_as_a_query_parameter(self):
        """The endpoint reads repeated ids= query params, not a body."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.cancel_collections(ids=[_COLLECTION_ID_A, _COLLECTION_ID_B])

        self.assertEqual(self.called_operation(), "DeleteCollectionsV1")
        self.assertEqual(
            self.called_kwargs()["parameters"],
            {"ids": [_COLLECTION_ID_A, _COLLECTION_ID_B]},
        )
        self.assertNotIn("body", self.called_kwargs())

    def test_surrounding_whitespace_is_stripped(self):
        """Copy-pasted ids with whitespace would otherwise fail to parse server-side."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        self.cancel_collections(ids=[f"  {_COLLECTION_ID_A} "])

        self.assertEqual(
            self.called_kwargs()["parameters"], {"ids": [_COLLECTION_ID_A]}
        )

    def test_partial_cancellation_is_flagged(self):
        """IDs the server did not cancel are named, with the likely reason.

        A partially-applied cancel returns 200, so without this diff a caller
        would report every requested run as stopped while some kept collecting.
        """
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        result = self.cancel_collections(ids=[_COLLECTION_ID_A, _COLLECTION_ID_B])

        self.assertEqual(result["cancelled_count"], 1)
        self.assertEqual(result["requested_count"], 2)
        self.assertEqual(result["not_cancelled"], [_COLLECTION_ID_B])
        self.assertIn("already complete", result["warning"])

    def test_id_casing_does_not_produce_a_false_warning(self):
        """Server ids are lowercase hex; an uppercase request must still match."""
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        result = self.cancel_collections(ids=[_COLLECTION_ID_A.upper()])

        self.assertNotIn("not_cancelled", result)

    def test_dashed_ids_are_compared_as_given(self):
        """Matching is literal apart from case: a dashed id will not match.

        The API returns dashless lowercase hex, so a dashed UUID is reported
        under not_cancelled even though the server did cancel it. This is an
        accepted limitation rather than a bug — the `ids` description tells
        callers to pass ids through from search_collections unmodified, which
        is the only documented source. This test exists so the behaviour is
        recorded, and so a future decision to normalize is a deliberate change
        to this assertion rather than a silent one.
        """
        dashed = "99998888-7777-6666-5555-444433332222"
        self.mock_client.command.return_value = _ok([{"id": _COLLECTION_ID_A}])

        result = self.cancel_collections(ids=[dashed])

        self.assertEqual(result["not_cancelled"], [dashed])

    def test_records_without_an_id_are_ignored_in_the_diff(self):
        """A record missing `id` must not raise while computing the diff."""
        self.mock_client.command.return_value = _ok([{"state": "cancelling"}])

        result = self.cancel_collections(ids=[_COLLECTION_ID_A])

        self.assertEqual(result["cancelled_count"], 0)
        self.assertEqual(result["not_cancelled"], [_COLLECTION_ID_A])

    def test_nothing_to_cancel_is_not_an_error(self):
        """A 404 means the runs already finished; nothing changed.

        Framing this as a failure invites a pointless retry. The message says
        explicitly that no state changed and points at search_collections.
        """
        self.mock_client.command.return_value = _err(404, ["collection not found"])

        result = self.cancel_collections()

        self.assertNotIn("error", result)
        self.assertTrue(result["no_collections_cancelled"])
        self.assertEqual(result["cancelled_count"], 0)
        self.assertIn("not an error", result["message"])

    def test_no_ids_refuses_without_an_api_call(self):
        """An empty id list is refused rather than sent as a broad cancel."""
        result = self.cancel_collections(ids=[])

        self.assertIn("error", result)
        self.assertIn("search_collections", result["error"])
        self.mock_client.command.assert_not_called()

    def test_over_the_cancel_cap_makes_no_api_call(self):
        """IDs ride in the URL, so the batch cap is enforced before sending.

        Exceeding it server-side surfaces as an opaque 414 or, worse, a
        truncated id list that cancels a silent subset.
        """
        result = self.cancel_collections(
            ids=[_COLLECTION_ID_A] * (_MAX_CANCEL_COLLECTION_IDS + 1)
        )

        self.assertIn("error", result)
        self.assertIn(str(_MAX_CANCEL_COLLECTION_IDS), result["error"])
        self.assertIn("Split into batches", result["error"])
        self.mock_client.command.assert_not_called()

    def test_at_the_cancel_cap_is_allowed(self):
        """Exactly the maximum is accepted."""
        self.mock_client.command.return_value = _ok([])

        self.cancel_collections(ids=[_COLLECTION_ID_A] * _MAX_CANCEL_COLLECTION_IDS)

        self.mock_client.command.assert_called_once()

    def test_total_failure_states_nothing_was_cancelled(self):
        """With no records returned, the response says nothing was cancelled."""
        self.mock_client.command.return_value = _err(500, ["failed to cancel"])

        result = self.cancel_collections()

        self.assertIn("No collections were cancelled", result["error"])
        self.assertEqual(result["details"]["trace_id"], "trace-1")

    def test_partial_failure_is_distinguished_from_total_failure(self):
        """When some records came back, the wording must not claim nothing happened."""
        self.mock_client.command.return_value = _err(
            500, ["partial failure"], resources=[{"id": _COLLECTION_ID_A}]
        )

        result = self.cancel_collections()

        self.assertIn("partially failed", result["error"])
        self.assertEqual(len(result["details"]["collections"]), 1)


class TestDeployCollectors(ForensicsTestCase):
    """deploy_collectors."""

    def test_success_reports_counts_and_collectors(self):
        """Deployed collectors and both counts come back for comparison."""
        self.mock_client.command.return_value = _ok(
            [{"aid": _AID_A, "ffcid": _FFCID_A, "state": "deploying"}],
            trace_id="tr-deploy",
        )

        result = self.deploy_collectors(aids=[_AID_A])

        self.assertEqual(result["deployed_count"], 1)
        self.assertEqual(result["requested_count"], 1)
        self.assertEqual(result["collectors"][0]["ffcid"], _FFCID_A)
        self.assertEqual(result["trace_id"], "tr-deploy")
        self.assertNotIn("not_deployed", result)

    def test_body_shape_and_whitespace_stripping(self):
        """queue_offline is always sent; aids are stripped."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        self.deploy_collectors(aids=[f" {_AID_A} ", _AID_B], queue_offline=True)

        self.assertEqual(self.called_operation(), "PostDeployV1")
        self.assertEqual(
            self.called_kwargs()["body"],
            {"aids": [_AID_A, _AID_B], "queue_offline": True},
        )

    def test_silently_skipped_hosts_are_flagged(self):
        """Hosts the API omitted are named rather than assumed deployed.

        The endpoint returns 200 and simply leaves out hosts that already have
        a session or are unknown, so only a diff against the request reveals
        that a host was never touched.
        """
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        result = self.deploy_collectors(aids=[_AID_A, _AID_B])

        self.assertEqual(result["deployed_count"], 1)
        self.assertEqual(result["not_deployed"], [_AID_B])
        self.assertIn("already online or deploying", result["warning"])

    def test_aid_casing_does_not_produce_a_false_warning(self):
        """An uppercase request still matches the lowercase AID returned."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        result = self.deploy_collectors(aids=[_AID_A.upper()])

        self.assertNotIn("not_deployed", result)

    def test_no_aids_makes_no_api_call(self):
        """An empty aid list is refused locally."""
        result = self.deploy_collectors(aids=[])

        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_over_the_aid_cap_makes_no_api_call(self):
        """Oversized batches are rejected with a batching instruction."""
        result = self.deploy_collectors(
            aids=[_AID_A] * (_MAX_DEPLOY_OR_SHUTDOWN_AIDS + 1)
        )

        self.assertIn("error", result)
        self.assertIn("Split into batches", result["error"])
        self.mock_client.command.assert_not_called()

    def test_proxy_settings_are_all_or_nothing(self):
        """Half-specified or contradictory proxy settings are refused locally.

        A partial proxy spec is accepted by the endpoint and then quietly
        ignored, so the collector deploys with the wrong network path and the
        caller never learns why it cannot phone home.
        """
        cases = {
            "no_proxy with host": {"no_proxy": True, "proxy_host": "p.example.test"},
            "no_proxy with port": {"no_proxy": True, "proxy_port": 8080},
            "host without port": {"proxy_host": "p.example.test"},
            "port without host": {"proxy_port": 8080},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                self.mock_client.command.reset_mock()
                result = self.deploy_collectors(**overrides)
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()

    def test_complete_proxy_settings_are_forwarded(self):
        """Host and port together are valid and reach the API."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        self.deploy_collectors(proxy_host="p.example.test", proxy_port=8080)

        body = self.called_kwargs()["body"]
        self.assertEqual(body["proxy_host"], "p.example.test")
        self.assertEqual(body["proxy_port"], 8080)
        self.assertNotIn("no_proxy", body)

    def test_no_proxy_is_sent_only_when_true(self):
        """no_proxy=False is omitted so it is not read as an explicit opt-out."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        self.deploy_collectors(no_proxy=True)
        self.assertIs(self.called_kwargs()["body"]["no_proxy"], True)

        self.mock_client.command.reset_mock()
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])
        self.deploy_collectors(no_proxy=False)
        self.assertNotIn("no_proxy", self.called_kwargs()["body"])

    def test_out_of_range_proxy_port_makes_no_api_call(self):
        """A port outside 1-65535 is rejected locally."""
        for port in (0, 70000):
            with self.subTest(port=port):
                self.mock_client.command.reset_mock()
                result = self.deploy_collectors(
                    proxy_host="p.example.test", proxy_port=port
                )
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()

    def test_unknown_aids_404_states_nothing_deployed(self):
        """A 404 reports that no collectors were deployed."""
        self.mock_client.command.return_value = _err(404, ["aid not found"])

        result = self.deploy_collectors()

        self.assertIn("No collectors were deployed", result["error"])

    def test_partial_failure_is_distinguished_from_total_failure(self):
        """With some collectors returned, the wording reflects partial progress."""
        self.mock_client.command.return_value = _err(
            500, ["failed to deploy"], resources=[{"aid": _AID_A}]
        )

        result = self.deploy_collectors(aids=[_AID_A, _AID_B])

        self.assertIn("partially failed", result["error"])
        self.assertEqual(len(result["details"]["collectors"]), 1)


class TestShutdownCollectors(ForensicsTestCase):
    """shutdown_collectors."""

    def test_success_echoes_self_destruct(self):
        """The response records whether the binary was also removed.

        self_destruct is not reversible from here — redeploying needs a fresh
        deploy call — so the caller needs it stated in the result, not just in
        the request it sent.
        """
        self.mock_client.command.return_value = _ok(
            [{"aid": _AID_A, "ffcid": _FFCID_A}], trace_id="tr-shutdown"
        )

        result = self.shutdown_collectors(self_destruct=True)

        self.assertEqual(result["shutdown_count"], 1)
        self.assertIs(result["self_destruct"], True)
        self.assertEqual(result["trace_id"], "tr-shutdown")
        self.assertNotIn("not_shutdown", result)

    def test_body_always_sends_both_target_lists_and_both_flags(self):
        """Absent lists become []; flags are sent explicitly."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        self.shutdown_collectors(
            aids=[f" {_AID_A} "], ffcids=[f" {_FFCID_A} "], self_destruct=True, force=True
        )

        self.assertEqual(self.called_operation(), "PostCollectorsV1")
        self.assertEqual(
            self.called_kwargs()["body"],
            {
                "aids": [_AID_A],
                "ffcids": [_FFCID_A],
                "self_destruct": True,
                "force": True,
            },
        )

    def test_ffcid_only_request_is_allowed(self):
        """Targeting a specific collector instance by ffcid alone is valid."""
        self.mock_client.command.return_value = _ok([{"ffcid": _FFCID_A}])

        result = self.shutdown_collectors(aids=None, ffcids=[_FFCID_A])

        self.assertEqual(self.called_kwargs()["body"]["aids"], [])
        self.assertNotIn("not_shutdown", result)

    def test_targets_are_matched_on_either_identifier(self):
        """A record matches whether it reports the aid or the ffcid.

        Resources carry both fields, so matching only one would report a
        successfully stopped collector as missed.
        """
        self.mock_client.command.return_value = _ok(
            [{"aid": _AID_A, "ffcid": None}, {"aid": None, "ffcid": _FFCID_A}]
        )

        result = self.shutdown_collectors(aids=[_AID_A], ffcids=[_FFCID_A])

        self.assertNotIn("not_shutdown", result)

    def test_unmatched_targets_are_flagged(self):
        """Targets with nothing running are named rather than reported as stopped."""
        self.mock_client.command.return_value = _ok([{"aid": _AID_A}])

        result = self.shutdown_collectors(aids=[_AID_A, _AID_B])

        self.assertEqual(result["not_shutdown"], [_AID_B])
        self.assertIn("search_collectors", result["warning"])

    def test_no_targets_refuses_without_an_api_call(self):
        """An untargeted shutdown is refused; it would be a fleet-wide action.

        Falling through with empty lists risks the endpoint interpreting the
        request as "all collectors for this CID", which cannot be undone.
        """
        result = self.shutdown_collectors(aids=None, ffcids=None)

        self.assertIn("error", result)
        self.assertIn("Refusing to shut down", result["error"])
        self.mock_client.command.assert_not_called()

    def test_empty_target_lists_refuse_without_an_api_call(self):
        """Two empty lists are still no targets."""
        result = self.shutdown_collectors(aids=[], ffcids=[])

        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_target_count_is_capped_across_both_lists(self):
        """The cap applies to aids + ffcids combined."""
        half = _MAX_DEPLOY_OR_SHUTDOWN_AIDS // 2 + 1
        result = self.shutdown_collectors(
            aids=[_AID_A] * half, ffcids=[_FFCID_A] * half
        )

        self.assertIn("error", result)
        self.assertIn("Split into batches", result["error"])
        self.mock_client.command.assert_not_called()

    def test_nothing_running_is_not_an_error_and_not_a_force_prompt(self):
        """A 404 means nothing was running; it must not suggest retrying with force.

        force can abandon an in-progress collection and lose its data, so a
        benign "nothing to stop" result explicitly steers away from it.
        """
        self.mock_client.command.return_value = _err(404, ["no in progress collectors"])

        result = self.shutdown_collectors()

        self.assertNotIn("error", result)
        self.assertTrue(result["no_collectors_in_progress"])
        self.assertEqual(result["shutdown_count"], 0)
        self.assertIn("Do not retry with force=true", result["message"])

    def test_total_failure_surfaces_status_and_trace(self):
        """A 500 with no records reports plain failure."""
        self.mock_client.command.return_value = _err(500, ["failed to shutdown"])

        result = self.shutdown_collectors()

        self.assertIn("Shutdown failed (HTTP 500)", result["error"])
        self.assertEqual(result["details"]["trace_id"], "trace-1")

    def test_partial_failure_is_distinguished(self):
        """With some records returned, the wording reflects partial progress."""
        self.mock_client.command.return_value = _err(
            500, ["partial"], resources=[{"aid": _AID_A}]
        )

        result = self.shutdown_collectors(aids=[_AID_A, _AID_B])

        self.assertIn("partially failed", result["error"])


if __name__ == "__main__":
    unittest.main()
