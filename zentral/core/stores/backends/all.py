from importlib import import_module
import logging
from django.core.exceptions import ImproperlyConfigured
from django.db import models


logger = logging.getLogger("zentral.core.events.stores.all")


class StoreBackend(models.TextChoices):
    ClickHouse = "CLICKHOUSE", "ClickHouse"
    Datadog = "DATADOG", "Datadog"
    Elasticsearch = "ELASTICSEARCH", "Elasticsearch"
    HTTP = "HTTP", "HTTP"
    Kinesis = "KINESIS", "Kinesis"
    OpenSearch = "OPENSEARCH", "OpenSearch"
    Panther = "PANTHER", "Panther"
    S3Parquet = "S3_PARQUET", "S3 Parquet"
    Snowflake = "SNOWFLAKE", "Snowflake"
    Splunk = "SPLUNK", "Splunk"
    SumoLogic = "SUMO_LOGIC", "Sumo Logic"


COMMUNITY_STORE_BACKENDS = (
    StoreBackend.ClickHouse, StoreBackend.Elasticsearch, StoreBackend.HTTP,
    StoreBackend.Kinesis, StoreBackend.OpenSearch, StoreBackend.S3Parquet,
)


def get_store_backend(store, load=False):
    backend = StoreBackend(store.backend)
    if backend not in COMMUNITY_STORE_BACKENDS:
        raise ImproperlyConfigured("Store backend is unavailable in the community runtime")
    try:
        module = import_module(f"zentral.core.stores.backends.{backend.value.lower()}")
        backend_cls = getattr(module, f"{backend.name}Store")
    except (ImportError, AttributeError):
        logger.exception("Could not load store backend %s", backend)
        raise
    return backend_cls(store, load)
