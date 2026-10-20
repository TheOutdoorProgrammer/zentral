from unittest.mock import Mock, patch

from django.apps import apps
from django.test import TestCase

from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.models import Store
from zentral.core.stores.provisioning import StoreProvisioner
from zentral.core.stores.serializers import StoreProvisioningSerializer
from zentral.utils.provisioning import iter_provisioners


class CommunityRuntimeTests(TestCase):
    def test_opensearch_provisioner_is_loaded_and_creates_store(self):
        self.assertTrue(any(isinstance(item, StoreProvisioner) for item in iter_provisioners()))
        serializer = StoreProvisioningSerializer(data={
            "name": "OpenSearch", "backend": "OPENSEARCH", "admin_console": True,
            "opensearch_kwargs": {"hosts": ["http://127.0.0.1:9200"], "index": "zentral-events"},
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        store = serializer.save(provisioning_uid="opensearch")
        self.assertEqual(Store.objects.get().get_backend().__class__.__name__, "OpenSearchStore")
        self.assertEqual(store.provisioning_uid, "opensearch")

    def test_enterprise_backend_is_not_a_community_choice(self):
        serializer = StoreProvisioningSerializer(data={"name": "Unavailable", "backend": "DATADOG"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("backend", serializer.errors)

    def test_opensearch_versions_use_typeless_indexing_and_calendar_histograms(self):
        for version in ("1.3.20", "2.19.0", "3.9.0"):
            with self.subTest(version=version):
                serializer = StoreProvisioningSerializer(data={
                    "name": f"OpenSearch {version}", "backend": "OPENSEARCH",
                    "opensearch_kwargs": {
                        "hosts": ["http://127.0.0.1:9200"], "index": "zentral-events", "batch_size": 10,
                    },
                })
                self.assertTrue(serializer.is_valid(), serializer.errors)
                store = serializer.save().get_backend(load=True)
                client = Mock()
                client.info.return_value = {"version": {"number": version}}
                client.indices.exists.return_value = False
                client.indices.recovery.return_value = {}
                event = LoginEvent(EventMetadata(), {"user": {"username": "synthetic-verification"}})
                with patch.object(store, "client_class", return_value=client):
                    store.store(event)
                self.assertEqual(store.version, [int(part) for part in version.split(".")])
                self.assertEqual(client.indices.create.call_args.kwargs["body"]["mappings"], store.MAPPINGS)
                self.assertNotIn("doc_type", client.index.call_args.kwargs)
                self.assertFalse(store.use_mapping_types)
                self.assertEqual(store._get_type_filter("login"), {"term": {"type": "login"}})
                histogram = store._get_hist_date_histogram_dict("day", 7)
                self.assertEqual(histogram["calendar_interval"], "day")
                self.assertNotIn("interval", histogram)
                with patch.object(store, "_streaming_bulk", return_value=iter(())) as bulk:
                    self.assertEqual(list(store.bulk_store([event])), [])
                    action = next(bulk.call_args.kwargs["actions"])
                    self.assertEqual(action["_index"], "zentral-events")
                    self.assertNotIn("_type", action)

    def test_elasticsearch_retains_legacy_version_capabilities(self):
        from zentral.core.stores.backends.elasticsearch import ElasticsearchStore
        store = object.__new__(ElasticsearchStore)
        for version, typeless, calendar in (
            ([6, 8], False, False), ([7, 0], True, False), ([7, 2], True, True), ([8, 0], True, True),
        ):
            with self.subTest(version=version):
                store.version = version
                self.assertEqual(store.uses_typeless_api, typeless)
                self.assertEqual(store.supports_calendar_interval, calendar)

    def test_optional_module_may_be_absent_but_broken_dependencies_fail_startup(self):
        config = apps.get_app_config("stores")
        missing_module = config.name + ".absent"
        with patch("zentral.utils.apps.import_module",
                   side_effect=ModuleNotFoundError(name=missing_module)):
            config._import_submodule("absent")
        with patch("zentral.utils.apps.import_module",
                   side_effect=ModuleNotFoundError(name="unavailable_dependency")):
            with self.assertRaises(ModuleNotFoundError):
                config._import_submodule("provisioning")

    def test_url_loading_does_not_hide_broken_dependencies(self):
        from server.urls import build_urlpatterns_for_zentral_apps
        with patch("server.urls.include", side_effect=ModuleNotFoundError(name="unavailable_dependency")):
            with self.assertRaises(ModuleNotFoundError):
                build_urlpatterns_for_zentral_apps()
