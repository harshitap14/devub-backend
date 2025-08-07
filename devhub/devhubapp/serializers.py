from rest_framework import serializers
from .models import Administrator
from .models import CardContent



from rest_framework import serializers
from devhubapp.models import Administrator

class AdminCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Administrator
        fields = [
            "first_name",
            "last_name",
            "email",
            "role",
            "phone",
            "city",
            "country",
            "photo",
        ]


    def validate_role(self, value):
        request = self.context.get("request")

        if not request or not request.user or not request.user.is_authenticated:
            return value  # Allow unauthenticated or anonymous creation (optional)

        try:
            current_admin = Administrator.objects.get(email=request.user.email)
        except Administrator.DoesNotExist:
            return value  # No admin record found; allow (e.g., for first superadmin)

        # Role restriction: Admins cannot assign SuperAdmin role
        if current_admin.role == "Admin" and value != "Admin":
            raise serializers.ValidationError("Admins cannot create or promote to SuperAdmin.")

        return value


class AdminSerializer(serializers.ModelSerializer):
    """
    General serializer for Admin details (read/update operations).
    """

    class Meta:
        model = Administrator
        fields = [
            "id",
            "name",
            "email",
            "role",
            "status",
            "first_name",
            "last_name",
            "full_name",
            "phone",
            "photo",
            "city",
            "country",
            "last_login",
            "created_at",
            "updated_at",
            "created_by",
            "updated_by",
        ]
        read_only_fields = [
            "id",
            "full_name",
            "created_at",
            "updated_at",
            "last_login",
        ]
    def validate_role(self, value):
      user = self.context["request"].user
      if user.role == "Admin" and value != "Admin":
        raise serializers.ValidationError("You are not allowed to assign roles other than 'Admin'.")
      return value

   



from rest_framework import serializers
from .models import Deck, Category, AppUser

class DeckSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deck
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    deck_name = serializers.CharField(source='deck.name', read_only=True)

    class Meta:
        model = Category
        fields = '__all__'


class AppUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppUser
        fields = ['id', 'first_name', 'last_name', 'email', 'email_verified', 'status', 'created_at', 'updated_at', 'last_login']
        
        

class CardContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CardContent
        fields = '__all__'
        read_only_fields = ['created_by', 'updated_by']

from rest_framework import serializers
from .models import UserLike, UserBookmark, UtilityActivity, UtilityActivityFile

class UserLikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLike
        fields = '__all__'

class UserBookmarkSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserBookmark
        fields = '__all__'

class UtilityActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UtilityActivity
        fields = '__all__'

class UtilityActivityFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UtilityActivityFile
        fields = '__all__'

# serializers.py
class CardContentStatsSerializer(serializers.ModelSerializer):
    like_count = serializers.IntegerField(read_only=True)
    bookmark_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = CardContent
        fields = ['id', 'name', 'short_description', 'read_time', 'like_count', 'bookmark_count']
