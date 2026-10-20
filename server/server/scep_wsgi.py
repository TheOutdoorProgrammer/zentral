import os

from django.core.wsgi import get_wsgi_application


os.environ["DJANGO_SETTINGS_MODULE"] = "server.scep_settings"
application = get_wsgi_application()
