from django.urls import include, path
from . import public_views
from . import up_views
from realms.backends.ldap.public_urls import urlpatterns as ldap_urlpatterns
from zentral.conf import settings as zentral_settings


app_name = "realms_public"
urlpatterns = [
    # SSO login
    path('<uuid:pk>/login/', public_views.LoginView.as_view(), name='login'),

    # User portal
    path('<uuid:realm_pk>/up/', up_views.IndexView.as_view(), name='up_index'),
    path('<uuid:realm_pk>/up/logout/', up_views.LogoutView.as_view(), name='up_logout'),
]
urlpatterns += ldap_urlpatterns


def build_user_portal_urlpatterns():
    """Builds urlpatterns object from the Zentral app configurations.

    Returns:
        urlpatterns: a list of path or re_path elements
    """
    urlpatterns = []
    for app_name, app_config in zentral_settings.get('apps', {}).items():
        if not app_config.get("user_portal", False):
            continue
        app_shortname = app_name.rsplit('.', 1)[-1]
        try:
            urlpatterns.append(path(f"<uuid:realm_pk>/up/{app_shortname}/", include(f"{app_name}.up_urls")))
        except ModuleNotFoundError:
            pass
    return urlpatterns


urlpatterns.extend(build_user_portal_urlpatterns())
