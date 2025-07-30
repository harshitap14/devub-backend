from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password


# ---------------------------------------------------------------------------
# Administrator Model
# ---------------------------------------------------------------------------
class Administrator(models.Model):
    ROLE_CHOICES = (
        ("Admin", "Admin"),
        ("SuperAdmin", "Super Admin"),
    )

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
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

class AppUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)

class AppUser(AbstractBaseUser, PermissionsMixin):
    STATUS_CHOICES = (
        ("Pending", "Pending"),
        ("Done", "Done"),
    )

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="Pending")
    last_login = models.DateTimeField(default=timezone.now)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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
