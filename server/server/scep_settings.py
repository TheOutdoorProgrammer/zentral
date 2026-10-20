from .settings import *  # noqa: F403


ROOT_URLCONF = "server.scep_urls"
MIDDLEWARE = [
    "zentral.telemetry.TelemetryMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
]
