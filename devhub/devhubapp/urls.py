# devhubapp/urls.py
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
from django.conf.urls.static import static
from .api_views import (
    AdminListCreateAPIView,
    AdminRetrieveUpdateDestroyAPIView,
    AdminLoginView,
    admin_password_set_api,
    admin_password_reset_request_api,
    AdminPasswordChangeView,
    AdminPasswordResetConfirmAPIView,
    AdminUpdateOnlyView,
    admin_logout_api,
    PasswordChangeDoneAPIView,
    AdminPhotoUploadView,
)

urlpatterns = [
    #update
     path("admins/update/<int:pk>/", AdminUpdateOnlyView.as_view(), name="admin_update"),

    # List/Create
    path("admins/", AdminListCreateAPIView.as_view(), name="admin_list_create"),
    # Retrieve/Delete
    path("admins/<int:pk>/", AdminRetrieveUpdateDestroyAPIView.as_view(), name="admin_detail"),

    # Auth flows
    
    path("admins/login/", AdminLoginView.as_view(), name="admin_login"),
    path("admins/password/set/", admin_password_set_api, name="admin_password_set"),
    path("admins/password/reset/", admin_password_reset_request_api, name="admin_password_reset_request"),
    path("admins/password/reset/done/", AdminPasswordResetConfirmAPIView.as_view(), name="admin_password_reset_request_done"),
    path("admins/password/change/", AdminPasswordChangeView.as_view(), name="admin_password_change"),
    path("admins/password/change/done/", PasswordChangeDoneAPIView.as_view(), name="password_change_done"),
    path('admins/photo/upload/', AdminPhotoUploadView.as_view(), name='admin-photo-upload'),

    # Optional: DRF built-in token (username/password to Django user)
    path("token/", obtain_auth_token, name="api_token"),
    #logout
    path("admins/logout/", admin_logout_api, name="admin_logout")
]

#if settings.DEBUG:
    #urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)