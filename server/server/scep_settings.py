from . import settings as base_settings


# The base module exports only celery_app through __all__, so wildcard import loses Django settings.
globals().update({name: value for name, value in vars(base_settings).items() if name.isupper()})
ROOT_URLCONF = "server.scep_urls"
MIDDLEWARE = [
    "zentral.telemetry.TelemetryMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
]
