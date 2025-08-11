"""devhubapp/api_views.py
Cleaned and corrected API views for Administrator management.
"""
from __future__ import annotations
from rest_framework.parsers import MultiPartParser, FormParser
import logging
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
from django.contrib.auth import logout
from django.contrib.auth import get_user_model
from botocore.exceptions import ClientError
import random
import string
from django.utils import timezone
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from .models import AppUser
from .models import OTPVerification
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from devhubapp.utils import get_or_create_shadow_user_for_appuser  # adjust import path
from workos import WorkOSClient
import os
from .supabase_upload import upload_image_fileobj, build_public_url
from .models import Administrator
from .serializers import AdminCreateSerializer, AdminSerializer, AppUserSerializer
from .email_utils import (
    
    send_admin_welcome_email,
    send_admin_reset_email,
    generate_uid_and_token
)
from .utils import get_or_create_shadow_user_for_admin, get_or_create_shadow_user_for_appuser
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
from django.db.models import Count
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import Administrator, CardContent
from .serializers import AdminSerializer, AdminCreateSerializer, CardContentStatsSerializer
from .utils import get_or_create_shadow_user_for_admin
from .email_utils import send_admin_welcome_email
import logging

logger = logging.getLogger(__name__)

class AdminListCreateAPIView(generics.ListCreateAPIView):
    # This is the line that was missing and caused the error
    queryset = Administrator.objects.all()
    permission_classes = [AllowAny]

    def get_serializer_class(self):
        return AdminCreateSerializer if self.request.method == "POST" else AdminSerializer

    def create(self, request, *args, **kwargs):
        serializer = AdminCreateSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        admin = Administrator.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data["email"],
            role=data.get("role", "Admin"),
            status=True,
            created_by=request.user.email if request.user.is_authenticated else None,
            updated_by=request.user.email if request.user.is_authenticated else None

        )
        admin.set_password("!")
        admin.save()

        try:
            get_or_create_shadow_user_for_admin(admin)
            send_admin_welcome_email(admin)
        except Exception as e:
            logger.exception("Failed to create shadow user or send admin welcome email: %s", e)

        return Response(AdminSerializer(admin).data, status=status.HTTP_201_CREATED)
# ------------------------------------------------------------------
# Admin Retrieve/Update/Delete
# ------------------------------------------------------------------
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from devhubapp.models import Administrator
from devhubapp.serializers import AdminCreateSerializer
from rest_framework.permissions import IsAuthenticated

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.response import Response
from devhubapp.models import Administrator
from devhubapp.serializers import AdminCreateSerializer

class AdminDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Administrator.objects.all()
    serializer_class = AdminCreateSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        print("🔐 Logged-in user:", request.user.email)

        try:
            Admin = Administrator.objects.get(email=request.user.email)
            print("✅ Matched Administrator:", Admin)
        except Administrator.DoesNotExist:
            print("❌ No matching Administrator")
            return Response({"error": "You are not an admin."}, status=status.HTTP_403_FORBIDDEN)
             
        if Admin.role.strip().lower() != 'superadmin':
            print("⛔ Not a SuperAdmin:", Admin.role)
            return Response({"error": "Only superadmins can delete admins."}, status=status.HTTP_403_FORBIDDEN)

        print("🗑️ SuperAdmin allowed to delete")
        return self.destroy(request, *args, **kwargs)


from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status
from rest_framework.response import Response
from .models import Administrator
from .serializers import AdminCreateSerializer


class AdminUpdateOnlyView(generics.UpdateAPIView):
    queryset = Administrator.objects.all()
    serializer_class = AdminCreateSerializer
    lookup_field = 'pk'
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        try:
            admin = Administrator.objects.get(email=request.user.email)
        except Administrator.DoesNotExist:
            return Response({"error": "You are not an admin."}, status=status.HTTP_403_FORBIDDEN)

        # Normalize role and remove role from request if not superadmin
        if ''.join(admin.role.split()).lower() != 'superadmin':
            if 'role' in request.data:
                print(f"⛔ Not allowed to change role: {admin.email}")
                request.data.pop('role', None)

        serializer = self.get_serializer(instance, data=request.data, partial=partial, context={"request": request})
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


# ------------------------------------------------------------------
# Admin Login
# ------------------------------------------------------------------
#from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model

from .models import Administrator
from .serializers import AdminSerializer
from .utils import get_or_create_shadow_user_for_appuser  # ✅ Ensure this works as expected

User = get_user_model()

class AdminLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            admin = Administrator.objects.get(email=email)
        except Administrator.DoesNotExist:
            return Response(
                {"error": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not admin.check_password(password):
            return Response(
                {"error": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Optional login tracking
        if hasattr(admin, "mark_login"):
            admin.mark_login()

        # Create or get shadow user to issue DRF token
        try:
            shadow_user = get_or_create_shadow_user_for_admin(admin)
        except Exception as e:
            return Response(
                {"error": "Failed to create shadow user.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Create or retrieve token for shadow user
        try:
            token, _ = Token.objects.get_or_create(user=shadow_user)
        except Exception as e:
            return Response(
                {"error": "Token creation failed.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response({
            "token": token.key,
            "admin": AdminSerializer(admin).data
        }, status=status.HTTP_200_OK)

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
    
from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Deck, Category, AppUser
from .serializers import DeckSerializer, CategorySerializer, AppUserSerializer
from rest_framework.decorators import action

# -----------------------------
# Deck CRUD
# -----------------------------
class DeckViewSet(viewsets.ModelViewSet):
    queryset = Deck.objects.all()
    serializer_class = DeckSerializer
    permission_classes = [AllowAny]



# -----------------------------
# Category CRUD
# -----------------------------
class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]



# -----------------------------
# AppUser: List + Delete Only
# -----------------------------
class AppUserViewSet(viewsets.ViewSet):
    def list(self, request):
        users = AppUser.objects.all()
        serializer = AppUserSerializer(users, many=True)
        return Response(serializer.data)

    def destroy(self, request, pk=None):
        try:
            user = AppUser.objects.get(pk=pk)
            user.delete()
            return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except AppUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@permission_classes([AllowAny])
class SignUpView(APIView):
    def post(self, request):
        data = request.data
        email = data.get("email")

        if AppUser.objects.filter(email).exists():
            return Response({"error": "Email already registered."}, status=400)

        user = AppUser(
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            email = email,
        )
        user.set_password(data.get("password"))
        user.save()

        otp = generate_otp()
        OTPVerification.objects.create(email=email, otp=otp)

        send_mail("Verify your Email", f"Your OTP is {otp}", "noreply@example.com", [email])

        return Response({"message": "Signup successful. Verify OTP sent to email."})

class SendEmailVerificationOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not AppUser.objects.filter(email).exists():
            return Response({"error": "User not found."}, status=404)

        otp = generate_otp()
        OTPVerification.objects.update_or_create(email=email, defaults={"otp": otp})
        send_mail("Verify your Email", f"Your OTP is {otp}", "noreply@example.com", [email])
        return Response({"message": "OTP sent for email verification."})
    
@permission_classes([AllowAny])
class VerifyEmailOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            otp_record = OTPVerification.objects.get(email=email, otp=otp)
            user = AppUser.objects.get(email=email)
            user.email_verified = True
            user.save()
            otp_record.delete()
            return Response({"message": "Email verified successfully."})
        except OTPVerification.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=400)



class UserLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email and password required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = AppUser.objects.get(email=email)
        except AppUser.DoesNotExist:
            return Response(
                {"error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.check_password(password):
            return Response(
                {"error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        shadow_user = get_or_create_shadow_user_for_appuser(user)
        token, _ = Token.objects.get_or_create(user=shadow_user)

        return Response({
            "token": token.key,
            "user": AppUserSerializer(user).data
        }, status=status.HTTP_200_OK)
        
class UpdatePasswordView(APIView):
    def post(self, request):
        email = request.data.get("email")
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        try:
            user = AppUser.objects.get(email=email)
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password updated successfully."})
            return Response({"error": "Incorrect old password."}, status=400)
        except AppUser.DoesNotExist:
            return Response({"error": "User not found."}, status=404)


password_reset_token = PasswordResetTokenGenerator()

@permission_classes([AllowAny])
class SendPasswordResetLinkView(APIView):
    def post(self, request):
        email = request.data.get("email")
        try:
            user = AppUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = password_reset_token.make_token(user)

            reset_url = request.build_absolute_uri(
                reverse('confirm_password_reset_link', kwargs={'uidb64': uid, 'token': token})
            )

            send_mail(
                "Password Reset Link",
                f"Click to reset your password: {reset_url}",
                "noreply@example.com",
                [email]
            )
            return Response({"message": "Password reset link sent to email."})
        except AppUser.DoesNotExist:
            return Response({"error": "User not found."}, status=404)


class ConfirmPasswordResetLinkView(APIView):
    def post(self, request, uidb64, token):
        new_password = request.data.get("new_password")

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = AppUser.objects.get(pk=uid)

            if password_reset_token.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password reset successful."})
            else:
                return Response({"error": "Invalid or expired token."}, status=400)
        except (TypeError, ValueError, OverflowError, AppUser.DoesNotExist):
            return Response({"error": "Invalid user."}, status=400)
        
class SignOutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"message": "Signed out successfully."})

from workos import WorkOSClient
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
from devhubapp.models import AppUser
from rest_framework.authtoken.models import Token
from django.contrib.auth import login as auth_login

# ✅ Correct WorkOS client
workos_client = WorkOSClient(
    api_key=settings.WORKOS_API_KEY,
    client_id=settings.WORKOS_CLIENT_ID
)

@permission_classes([AllowAny])
class GitHubLoginView(APIView):
    def get(self, request):
        try:
            # ✅ Use workos_client.sso to get authorization URL
            authorization_url = workos_client.sso.get_authorization_url(
                provider="GitHubOAuth",
                redirect_uri=settings.WORKOS_REDIRECT_URI,
            )
            return Response({"auth_url": authorization_url})
        except Exception as e:
            return Response({"error": f"Failed to get authorization URL: {e}"}, status=400)

@permission_classes([AllowAny])
class GitHubCallbackView(APIView):
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Missing code parameter."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile_and_token = workos_client.sso.get_profile_and_token(code=code)
            profile = profile_and_token.profile
            email = profile.email

            user, created = AppUser.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": profile.first_name or "",
                    "last_name": profile.last_name or "",
                }
            )

            user.backend = "django.contrib.auth.backends.ModelBackend"
            auth_login(request, user)
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "GitHub login successful",
                "token": token.key,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            })

        except Exception as e:
            return Response({"error": f"Authentication failed: {e}"}, status=400)

class UpdateUserProfileView(APIView):
    permission_classes = [AllowAny]

    def patch(self, request):
       #user = AppUser.objects.get(pk=pk)
        user = request.user
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name")

        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name

        user.save()

        return Response({
            "message": "Profile updated successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }, status=status.HTTP_200_OK)

from rest_framework import generics, permissions
from .models import CardContent
from .serializers import CardContentSerializer

# Create new card (used when admin creates a card)
class CardContentCreateView(generics.CreateAPIView):
    queryset = CardContent.objects.all()
    serializer_class = CardContentSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

# Update card content (esp. the rich text description field)
class CardContentUpdateView(generics.UpdateAPIView):
    queryset = CardContent.objects.all()
    serializer_class = CardContentSerializer
    permission_classes = [AllowAny]
    lookup_field = 'id'

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

# Display full card content (used by frontend)
class CardContentDetailView(generics.RetrieveAPIView):
    queryset = CardContent.objects.all()
    serializer_class = CardContentSerializer
    permission_classes = [permissions.AllowAny]  # or IsAuthenticated
    lookup_field = 'id'



class CardContentDeleteView(generics.DestroyAPIView):
    queryset = CardContent.objects.all()
    permission_classes = [AllowAny]
    lookup_field = 'id'

User = get_user_model()

class CardListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cards = CardContent.objects.all()
        serializer = CardContentSerializer(cards, many=True)
        return Response(serializer.data)

# views.py
from django.db.models import Count
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import CardContent
from .serializers import CardContentStatsSerializer

class MostLikedCardsAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cards = CardContent.objects.annotate(
            like_count=Count('likes'),
        ).order_by('-like_count')[:10]

        serializer = CardContentStatsSerializer(cards, many=True)
        return Response(serializer.data)

class MostBookmarkedCardsAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cards = CardContent.objects.annotate(
            bookmark_count=Count('bookmarks'),
        ).order_by('-bookmark_count')[:10]

        serializer = CardContentStatsSerializer(cards, many=True)
        return Response(serializer.data)



from rest_framework import viewsets
from .models import Administrator
from .serializers import AdminSerializer, AdminCreateSerializer
from .permissions import IsSuperAdminOrAdminCreateOnly
from rest_framework.exceptions import PermissionDenied


class AdministratorViewSet(viewsets.ModelViewSet):
    queryset = Administrator.objects.all()
    serializer_class = AdminSerializer
    permission_classes = [IsSuperAdminOrAdminCreateOnly]

    def perform_update(self, serializer):
        user = self.request.user
        instance = self.get_object()

        # Prevent admins from changing the role
        if user.role == 'admin' and 'role' in self.request.data:
            if self.request.data['role'] != instance.role:
                raise PermissionDenied("Admins are not allowed to change roles.")

        serializer.save()

    def perform_destroy(self, instance):
        user = self.request.user
        if user.role != 'superadmin':
            raise PermissionDenied("Only superadmins can delete users.")
        instance.delete()
