from rest_framework import permissions

class IsSuperAdminOrAdminCreateOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user

        # Allow GET for both superadmin and admin
        if view.action in ['list', 'retrieve']:
            return user.role in ['admin', 'superadmin']

        # Allow only superadmin to DELETE or UPDATE role
        if view.action in ['destroy', 'partial_update', 'update']:
            return user.role == 'superadmin'

        # Allow creating admin by both, but superadmin can create superadmin too
        if view.action == 'create':
            target_role = request.data.get('role')
            if user.role == 'superadmin':
                return True  # can create any
            elif user.role == 'admin':
                return target_role == 'admin'  # admin can only create admins

        return False
