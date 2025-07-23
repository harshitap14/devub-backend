from rest_framework import serializers
from .models import Administrator


class AdminCreateSerializer(serializers.ModelSerializer):
    """
    Used for creating a new admin via API (no password input).
    """
    class Meta:
        model = Administrator
        fields = [
            "first_name",
            "last_name",
            "email",
            "role",
            "phone",
            "address",
            "photo",
        ]


class AdminSerializer(serializers.ModelSerializer):
    """
    General serializer for Admin details (read operations).
    Includes phone, address, and photo fields.
    """
    # photo = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Administrator
        fields = [
            "id",
            "name",
            "email",
            "role",
            "status",
            "first_name",
            "last_name",
            "full_name",
            "phone",
            "address",
            "photo",
            "last_login_at",
            "created_at",
            "updated_at",
            "created_by",
            "updated_by",
        ]
        read_only_fields = [
            "id",
            "full_name",
            "created_at",
            "updated_at",
            "last_login_at",
        ]
