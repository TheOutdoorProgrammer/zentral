from rest_framework import serializers
from .models import Realm
from .backends.ldap.serializers import LDAPConfigSerializer


class RealmSerializer(serializers.ModelSerializer):
    ldap_config = LDAPConfigSerializer(
        source="get_ldap_config",
        required=False,
    )

    class Meta:
        model = Realm
        exclude = ("config",)
