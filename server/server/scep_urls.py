from django.db import transaction
from django.http import HttpResponse
from django.urls import path
from django.views.decorators.http import require_GET

from zentral.contrib.mdm.scep_views import authorize, challenge


@transaction.non_atomic_requests
@require_GET
def health(request):
    return HttpResponse("ok", content_type="text/plain")


urlpatterns = [
    path("healthz/", health),
    path("internal/mdm/scep/challenges/", challenge),
    path("internal/mdm/scep/authorize/", authorize),
]
