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
