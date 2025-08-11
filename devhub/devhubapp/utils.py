from django.contrib.auth import get_user_model

User = get_user_model()

def get_or_create_shadow_user_for_appuser(appuser):
    """
    Creates or retrieves a shadow User instance for a given AppUser (e.g., Administrator).
    Ensures DRF token authentication works by tying to a real User model.
    """

    user, created = User.objects.get_or_create(
        email=appuser.email,
        defaults={
            "username": appuser.email,  # ensure username is unique
            "first_name": appuser.first_name,
            "last_name": appuser.last_name,
        }
    )

    if created:
        # Set a default unusable password unless you want them to log in directly
        user.set_unusable_password()
        user.save()
    else:
        # Optional: update user fields if appuser details changed
        updated = False
        if user.first_name != appuser.first_name:
            user.first_name = appuser.first_name
            updated = True
        if user.last_name != appuser.last_name:
            user.last_name = appuser.last_name
            updated = True
        if user.email != appuser.email:
            user.email = appuser.email
            updated = True
        if updated:
            user.save()

    return user

def get_or_create_shadow_user_for_admin(admin):
    """
    Ensure the given Administrator instance has a linked Django auth_user.
    Creates one if missing and links it to the admin object.
    """
    # If Administrator model has a direct FK/OneToOne to auth_user
    if hasattr(admin, "user") and admin.user:
        return admin.user

    # Try to find a matching auth_user by email
    user, created = User.objects.get_or_create(
        username=admin.email,  # use email as username for uniqueness
        defaults={
            "first_name": admin.first_name,
            "last_name": admin.last_name,
            "email": admin.email,
            "is_active": True
        }
    )

    # Link this user to the admin instance (adjust field name if different)
    if hasattr(admin, "user"):
        admin.user = user
        admin.save(update_fields=["user"])

    return user

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

User = get_user_model()

def generate_uid_and_token(admin):
    """
    Ensure a matching User exists for the given admin instance,
    then return a base64 UID and the user's auth token.
    """
    # Ensure matching user in AUTH_USER_MODEL
    user, _ = User.objects.get_or_create(
        email=admin.email,
        defaults={
            "first_name": admin.first_name,
            "last_name": admin.last_name,
            "username": admin.email,   # use email as username for uniqueness
            "password": "!"            # placeholder (won't be used for login)
        }
    )

    # Create or retrieve the auth token
    token, _ = Token.objects.get_or_create(user=user)

    # Create base64 encoded user ID
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

    return uidb64, token.key
