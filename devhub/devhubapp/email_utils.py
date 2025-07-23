# devhubapp/email_utils.py
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import Administrator

# Token generator for admin password reset
admin_token_generator = PasswordResetTokenGenerator()

def generate_uid_and_token(admin: Administrator):
    """
    Generates a UID and token for a given Administrator object.
    """
    uid = urlsafe_base64_encode(force_bytes(admin.pk))
    token = admin_token_generator.make_token(admin)
    return uid, token


def send_admin_welcome_email(admin: Administrator):
    """
    Sends a welcome email with a set-password link.
    """
    uid, token = generate_uid_and_token(admin)
    set_link = f"{settings.FRONTEND_URL}/create_password?uid={uid}&token={token}"
    
    ctx = {
        "first_name": admin.first_name,
        "last_name": admin.last_name,
        "reset_link": set_link,
    }
    subject = "Your DevHub Admin Account"
    plain = f"Hello {admin.first_name},\n\nWelcome to DevHub! Set your password here:\n{set_link}"
    html = render_to_string("emails/admin_welcome_email.html", ctx)
    
    send_mail(
        subject, plain, settings.DEFAULT_FROM_EMAIL, [admin.email], html_message=html
    )


def send_admin_reset_email(admin: Administrator):
    """
    Sends a password reset email with a reset-password link.
    """
    uid, token = generate_uid_and_token(admin)
    reset_link = f"{settings.FRONTEND_URL}/reset?uid={uid}&token={token}"
    
    ctx = {
        "first_name": admin.first_name,
        "last_name": admin.last_name,
        "reset_link": reset_link,
    }
    subject = "Reset Your DevHub Admin Password"
    plain = f"Hello {admin.first_name},\n\nYou requested a password reset. Click the link below:\n{reset_link}"
    html = render_to_string("emails/admin_reset_password.html", ctx)
    
    send_mail(
        subject, plain, settings.DEFAULT_FROM_EMAIL, [admin.email], html_message=html
    )
