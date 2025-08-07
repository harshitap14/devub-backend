from rest_framework import permissions

class IsSuperAdminOrAdminCreateOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user

        # Allow GET for both superadmin and admin
        if view.action in ['list', 'retrieve']:
            return user.role in ['Admin', 'SuperAdmin']

        # Allow only superadmin to DELETE or UPDATE role
        if view.action in ['destroy', 'partial_update', 'update']:
            return user.role == 'SuperAdmin'

        # Allow creating admin by both, but superadmin can create superadmin too
        if view.action == 'create':
            target_role = request.data.get('role')
            if user.role == 'SuperAdmin':
                return True  # can create any
            elif user.role == 'Admin':
                return target_role == 'Admin'  # admin can only create admins

        return False
