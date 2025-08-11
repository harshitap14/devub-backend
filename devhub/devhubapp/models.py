from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import Permission
from django.db import models
from django.contrib.auth.models import Group, AbstractBaseUser, PermissionsMixin, BaseUserManager

class UserGroups(models.Model):
    user = models.ForeignKey('AppUser', on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)

    class Meta:
        db_table = 'users_groups'
        unique_together = ('user', 'group')
# ---------------------------------------------------------------------------
# Administrator Model
# ---------------------------------------------------------------------------
class Administrator(models.Model):
    ROLE_CHOICES = (
        ("Admin", "Admin"),
        ("SuperAdmin", "SuperAdmin"),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)


    # core identity
    name = models.CharField(max_length=200, blank=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="Admin")
    status = models.BooleanField(default=True)

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    full_name = models.CharField(max_length=205, blank=True)

    phone = models.CharField(max_length=15, blank=True, null=True)
    photo = models.TextField(blank=True, null=True)

    city = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)


    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    created_by = models.CharField(max_length=100, blank=True, null=True)
    updated_by = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        db_table = "administrators"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.full_name or self.email} ({self.role})"

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def mark_login(self):
        self.last_login = timezone.now()
        self.save(update_fields=["last_login"])

    def save(self, *args, **kwargs):
        fn = self.first_name.strip() if self.first_name else ""
        ln = self.last_name.strip() if self.last_name else ""
        full = (fn + " " + ln).strip()
        self.full_name = full
        self.name = full or self.name
        super().save(*args, **kwargs)

    def get_email_field_name(self):
        return 'email'

    def get_username(self):
        return self.email


# ---------------------------------------------------------------------------
# AppUser Model
# ---------------------------------------------------------------------------
class AppUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class AppUser(AbstractBaseUser, PermissionsMixin):
    # Only one role choice, as requested.
    ROLE_CHOICES = (
        ('user', 'User'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)

    STATUS_CHOICES = (
        ("Pending", "Pending"),
        ("Done", "Done"),
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="Pending")
    
    last_login = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Note: If you're using a custom through model, it should be defined here.
    groups = models.ManyToManyField(
        Group,
        through='UserGroups',
        blank=True,
        related_name='appuser_set',
        related_query_name='appuser'
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = AppUserManager()

    class Meta:
        db_table = "users"
        ordering = ["-created_at"]

    def __str__(self):
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email

    @property
    def name(self):
        return f"{self.first_name} {self.last_name}".strip()


# ---------------------------------------------------------------------------
# Deck Model
# ---------------------------------------------------------------------------
class Deck(models.Model):
    STATUS_CHOICES = (
        ("Active", "Active"),
        ("Inactive", "Inactive"),
    )

    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="Active")

    created_by = models.ForeignKey(Administrator, on_delete=models.SET_NULL, null=True, related_name="created_decks")
    updated_by = models.CharField(max_length=100, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "decks"
        ordering = ["-created_at"]

    def __str__(self):
        return self.name


# ---------------------------------------------------------------------------
# Category Model
# ---------------------------------------------------------------------------
class Category(models.Model):
    STATUS_CHOICES = (
        ("Active", "Active"),
        ("Inactive", "Inactive"),
    )

    name = models.CharField(max_length=100)
    deck = models.ForeignKey(Deck, on_delete=models.CASCADE, related_name="categories")
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="Active")

    created_by = models.ForeignKey(Administrator, on_delete=models.SET_NULL, null=True, related_name="created_categories")
    updated_by = models.CharField(max_length=100, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "categories"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} (Deck: {self.deck.name})"
    
from django.db import models
from django.utils import timezone
from datetime import timedelta

def default_expiry():
    return timezone.now() + timedelta(minutes=10)

class OTPVerification(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    expires_at = models.DateTimeField(default=default_expiry)

    
    class Meta:
        db_table = "otp_verifications"
        ordering = ["-created_at"]

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class CardContent(models.Model):
    deck_id = models.IntegerField()
    category_id = models.IntegerField()
    name = models.CharField(max_length=255)
    short_description = models.TextField()
    description = models.TextField()  # rich text (HTML) from editor
    status = models.CharField(max_length=20, default='draft')
    tags = models.CharField(max_length=255, blank=True)
    read_time = models.PositiveIntegerField()
    is_private = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, related_name='cards_created', on_delete=models.CASCADE)
    updated_by = models.ForeignKey(User, related_name='cards_updated', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class UserLike(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    card_content_id = models.ForeignKey('CardContent', on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True)
    updated_by = models.CharField(max_length=255, blank=True)
    class Meta:
        db_table = 'user_likes'

class UserBookmark(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    card_content_id = models.IntegerField()
    deck_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True)
    updated_by = models.CharField(max_length=255, blank=True)
    class Meta:
        db_table = 'user_bookmarks'
    
    

class UtilityActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    card_content_id = models.IntegerField()
    activity_output = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True)
    updated_by = models.CharField(max_length=255, blank=True)
    class Meta:
        db_table = 'utility_activity'

class UtilityActivityFile(models.Model):
    utility_activity = models.ForeignKey(UtilityActivity, on_delete=models.CASCADE, related_name='files')
    file_type = models.CharField(max_length=50)
    file_url = models.URLField()
    file_size = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True)
    updated_by = models.CharField(max_length=255, blank=True)
    class Meta:
        db_table = 'utility_activity_files'
