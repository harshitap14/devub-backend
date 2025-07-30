from django.contrib.auth.models import User

def get_or_create_shadow_user_for_appuser(appuser):
    user, created = User.objects.get_or_create(
        username=appuser.email,
        defaults={
            "first_name": appuser.first_name,
            "last_name": appuser.last_name,
            "email": appuser.email,
        }
    )

    # Optional: update user info in case AppUser info changed
    if not created:
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

