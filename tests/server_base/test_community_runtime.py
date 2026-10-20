from unittest.mock import patch

from django.apps import apps
from django.test import TestCase

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
