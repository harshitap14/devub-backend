# devhubapp/urls.py
from django.urls import path, include
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
    DeckViewSet, CategoryViewSet, AppUserViewSet,
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
    path("admins/<int:pk>/", AdminRetrieveUpdateDestroyAPIView.as_view(), name="admin_detail"),

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
]
