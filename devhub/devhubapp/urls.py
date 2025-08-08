# devhubapp/urls.py
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
from django.conf.urls.static import static
from .api_views import (
    AdminListCreateAPIView,
    AdminLoginView,
    admin_password_set_api,
    admin_password_reset_request_api,
    AdminPasswordChangeView,
    AdminPasswordResetConfirmAPIView,
    admin_logout_api,
    PasswordChangeDoneAPIView,
    AdminPhotoUploadView,
    DeckViewSet, 
    CategoryViewSet, 
    AppUserViewSet,
    VerifyEmailOTPView,
    SignUpView,
    UpdatePasswordView,
    SendPasswordResetLinkView,
    ConfirmPasswordResetLinkView,
    SendEmailVerificationOTPView,
    UserLoginView,
    SignOutView,
    GitHubLoginView,
    UpdateUserProfileView,
    CardContentCreateView,
    CardContentUpdateView,
    CardContentDetailView,
    CardContentDeleteView,
     CardListView,
     MostLikedCardsAPIView, 
     MostBookmarkedCardsAPIView,
    AdminDetailView,
    AdminUpdateOnlyView,
)

from rest_framework.routers import DefaultRouter
router = DefaultRouter()
router.register(r'decks', DeckViewSet, basename='deck')
router.register(r'categories', CategoryViewSet, basename='category')
# AppUser - Custom ViewSet (only list + delete)
user_list = AppUserViewSet.as_view({
    'get': 'list',
})
user_delete = AppUserViewSet.as_view({
    'delete': 'destroy',
})
urlpatterns = [
    path("admins/update/<int:pk>/", AdminUpdateOnlyView.as_view(), name="admin_update"),
    # List/Create
    path("admins/", AdminListCreateAPIView.as_view(), name="admin_list_create"),
    # Retrieve/Delete
    path("admins/<int:pk>/", AdminDetailView.as_view(), name="admin_detail"),
    # Auth flows
    path("admins/login/", AdminLoginView.as_view(), name="admin_login"),
    path("admins/password/set/", admin_password_set_api, name="admin_password_set"),
    path("admins/password/reset/", admin_password_reset_request_api, name="admin_password_reset_request"),
    path("admins/password/reset/done/", AdminPasswordResetConfirmAPIView.as_view(), name="admin_password_reset_request_done"),
    path("admins/password/change/", AdminPasswordChangeView.as_view(), name="admin_password_change"),
    path("admins/password/change/done/", PasswordChangeDoneAPIView.as_view(), name="password_change_done"),
    path('admins/photo/upload/', AdminPhotoUploadView.as_view(), name='admin-photo-upload'),
    # DRF built-in token auth
    path("token/", obtain_auth_token, name="api_token"),
    # Logout
    path("admins/logout/", admin_logout_api, name="admin_logout"),
    # ViewSets via router
    path('', include(router.urls)),
    # Custom AppUser endpoints
    path('users/', user_list, name='user-list'),
    path('users/<int:pk>/', user_delete, name='user-delete'),
    # User Authentication
    path("users/signup/", SignUpView.as_view(), name="signup"),
    path("users/login/", UserLoginView.as_view(), name="login"),
    path('users/logout/', SignOutView.as_view(), name='signout'),
    # Email Verification
    path("users/verify-email/send/", SendEmailVerificationOTPView.as_view(), name="send_email_verification_otp"),
    path("users/verify-email/confirm/", VerifyEmailOTPView.as_view(), name="verify_email_otp"), 
    # Update Password
    path("users/password/update/", UpdatePasswordView.as_view(), name="update_password"),
    path("users/profile/", UpdateUserProfileView.as_view(), name="update-user-profile"),
    # Password Reset via link
    path("users/password-reset/send/", SendPasswordResetLinkView.as_view(), name="send_password_reset_otp"),
     path('users/reset-confirm/<uidb64>/<token>/', ConfirmPasswordResetLinkView.as_view(), name='confirm_password_reset_link'),    
    #github
    path('login/github/', GitHubLoginView.as_view(), name='github_login'),
    #path('callback/', GitHubCallbackView.as_view(), name='github_callback')
    #card content management
    path('cards/delete/<int:id>/', CardContentDeleteView.as_view(), name='card-delete'),
    path('cards/', CardContentCreateView.as_view(), name='card-create'),
    path('cards/<int:id>/', CardContentDetailView.as_view(), name='card-detail'),
    path('cards/update/<int:id>/', CardContentUpdateView.as_view(), name='card-update'),
    path('cards/public/', CardListView.as_view()),
    #KPI's
    path('cards/most-liked/', MostLikedCardsAPIView.as_view(), name='most-liked-cards'),
    path('cards/most-bookmarked/', MostBookmarkedCardsAPIView.as_view(), name='most-bookmarked-cards'),
]
