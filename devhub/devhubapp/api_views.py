"""devhubapp/api_views.py
Cleaned and corrected API views for Administrator management.
"""
from __future__ import annotations
from rest_framework.parsers import MultiPartParser, FormParser
import logging
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from botocore.exceptions import ClientError

import os
from .supabase_upload import upload_image_fileobj, build_public_url
from .models import Administrator
from .serializers import AdminCreateSerializer, AdminSerializer
from .email_utils import (
    generate_uid_and_token,
    send_admin_welcome_email,
    send_admin_reset_email,
)

logger = logging.getLogger(__name__)
User = get_user_model()

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def validate_password_token(token_str):
    """
    Decode and verify the password set/reset token.
    Expects token_str in format "uidb64:token"
    Returns Administrator instance or None.
    """
    if not token_str or ':' not in token_str:
        return None
    try:
        uidb64, token = token_str.split(':', 1)
        uid = force_str(urlsafe_base64_decode(uidb64))
        admin = Administrator.objects.get(pk=uid)
    except Exception:
        return None

    token_generator = PasswordResetTokenGenerator()
    if token_generator.check_token(admin, token):
        return admin
    return None

def get_or_create_shadow_user_for_admin(admin: Administrator):
    """Ensure a Django auth user record exists for DRF TokenAuth."""
    try:
        u = User.objects.get(email=admin.email)
    except User.DoesNotExist:
        u = User.objects.create_user(username=admin.email, email=admin.email)
        u.set_unusable_password()
        u.is_staff = True
        u.is_active = True
        u.save()
    return u

def update_admin_and_shadow_password(admin: Administrator, raw_password: str) -> None:
    admin.set_password(raw_password)
    admin.save(update_fields=["password"])
    shadow_user = get_or_create_shadow_user_for_admin(admin)
    shadow_user.set_password(raw_password)
    shadow_user.save()

# ------------------------------------------------------------------
# Admin Create + List
# ------------------------------------------------------------------
class AdminListCreateAPIView(generics.ListCreateAPIView):
    queryset = Administrator.objects.all()
    permission_classes = [AllowAny]  # Allow unauthenticated access for listing

    def get_serializer_class(self):
        return AdminCreateSerializer if self.request.method == "POST" else AdminSerializer

    def create(self, request, *args, **kwargs):
        serializer = AdminCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        admin = Administrator.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data["email"],
            role=data.get("role", "Admin"),
            status=True,
            created_by=request.user.username if request.user.is_authenticated else None,
        )
        admin.set_password("!")  # placeholder
        admin.save()
        get_or_create_shadow_user_for_admin(admin)
        try:
            uidb64, token = generate_uid_and_token(admin)
            send_admin_welcome_email(admin)

        except Exception:
            logger.exception("Failed to send admin welcome email")
        return Response(AdminSerializer(admin).data, status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------
# Admin Retrieve/Update/Delete
# ------------------------------------------------------------------
class AdminRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Administrator.objects.all()
    serializer_class = AdminSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'put','delete']

class AdminUpdateOnlyView(generics.UpdateAPIView):
    queryset = Administrator.objects.all()
    serializer_class = AdminSerializer
    http_method_names = ['put']  # Allow only PUT requests


# ------------------------------------------------------------------
# Admin Login
# ------------------------------------------------------------------
class AdminLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        if not email or not password:
            return Response({"error": "Email and password required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            admin = Administrator.objects.get(email=email)
        except Administrator.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        if not admin.check_password(password):
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        if hasattr(admin, "mark_login"):
            admin.mark_login()
        shadow_user = get_or_create_shadow_user_for_admin(admin)
        token, _ = Token.objects.get_or_create(user=shadow_user)
        return Response({"token": token.key, "admin": AdminSerializer(admin).data})

# ------------------------------------------------------------------
# Admin Password Set (after welcome email)
# ------------------------------------------------------------------
@api_view(["POST"])
@permission_classes([permissions.AllowAny])
def admin_password_set_api(request):
    uidb64 = request.data.get("uid")
    token = request.data.get("token")
    password = request.data.get("password")
    confirm_password = request.data.get("confirm_password")
    if not all([uidb64, token, password, confirm_password]):
        return Response({"detail": "Missing fields."}, status=status.HTTP_400_BAD_REQUEST)
    if password != confirm_password:
        return Response({"detail": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
    if len(password) < 6:
        return Response({"detail": "Password too short."}, status=status.HTTP_400_BAD_REQUEST)
    # Fetch admin by UID
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        admin = Administrator.objects.get(pk=uid)
    except Exception:
        return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)
    # Validate token for this admin
    token_generator = PasswordResetTokenGenerator()
    if not token_generator.check_token(admin, token):
        return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
    update_admin_and_shadow_password(admin, password)
    return Response({"detail": "Password set. You may now log in."})


# ------------------------------------------------------------------
# Admin Password Reset Request
# ------------------------------------------------------------------
@api_view(["POST"])
@permission_classes([permissions.AllowAny])
def admin_password_reset_request_api(request):
    email = request.data.get("email")
    admin = Administrator.objects.filter(email=email).first()
    if admin:
        try:
            uidb64, token = generate_uid_and_token(admin)
            send_admin_reset_email(admin)
        except Exception:
            logger.exception("Failed sending reset email")
    return Response({"detail": "If the email exists, a reset link will be sent."})

# ------------------------------------------------------------------
# Password Change (authenticated)
# ------------------------------------------------------------------
class AdminPasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            admin = Administrator.objects.get(email=request.user.email)
        except Administrator.DoesNotExist:
            return Response({"detail": "Not an admin."}, status=status.HTTP_403_FORBIDDEN)
        new1 = request.data.get("new_password1")
        new2 = request.data.get("new_password2")
        if not new1 or not new2:
            return Response({"detail": "Both password fields required."}, status=status.HTTP_400_BAD_REQUEST)
        if new1 != new2:
            return Response({"detail": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
        if len(new1) < 6:
            return Response({"detail": "Password too short."}, status=status.HTTP_400_BAD_REQUEST)
        update_admin_and_shadow_password(admin, new1)
        return Response({"detail": "Password changed."})

# ------------------------------------------------------------------
# Password Reset Confirm
# ------------------------------------------------------------------
class AdminPasswordResetConfirmAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        password = request.data.get("password")
        confirm_password = request.data.get("password_confirm")
        if not uidb64 or not token or not password or not confirm_password:
            return Response({"error": "uid, token, password, and password_confirm are required."}, status=status.HTTP_400_BAD_REQUEST)
        if password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            admin = Administrator.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(admin, token):
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            shadow_user = get_or_create_shadow_user_for_admin(admin)
            validate_password(password, user=shadow_user)
        except DjangoValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)
        update_admin_and_shadow_password(admin, password)
        return Response({"success": True, "message": "Password reset successful."}, status=status.HTTP_200_OK)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_logout_api(request):
    try:
        # Delete the token to force re-authentication on future requests
        request.user.auth_token.delete()
    except AttributeError:
        # If the user was not logged in with a token or token not set
        pass
    return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)

class PasswordChangeDoneAPIView(APIView):
    """
    A simple API to confirm that password change has been completed.
    """
    def get(self, request):
        return Response(
            {"success": True, "message": "Password change process completed."},
            status=status.HTTP_200_OK
        )


class AdminPhotoUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file = request.FILES.get("photo") or request.FILES.get("image")
        if not file:
            return Response({"detail": "No image file provided."}, status=400)

        try:
            admin = Administrator.objects.get(email=request.user.email)
        except Administrator.DoesNotExist:
            return Response({"detail": "Admin not found."}, status=404)

        object_key = f"admins/{admin.id}/{file.name}"

        try:
            upload_image_fileobj(file, object_key)
        except ClientError as e:
            return Response({"detail": f"Upload failed: {e}"}, status=502)
        except Exception as e:
            return Response({"detail": f"Unexpected error: {e}"}, status=500)

        photo_url = build_public_url(object_key)
        admin.photo = photo_url  # Change model to URLField if needed
        admin.save(update_fields=["photo"])

        return Response({"success": True, "photo_url": photo_url}, status=200)