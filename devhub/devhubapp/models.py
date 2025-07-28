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

    last_login_at = models.DateTimeField(blank=True, null=True)

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
        self.last_login_at = timezone.now()
        self.save(update_fields=["last_login_at"])

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
class AppUser(models.Model):
    STATUS_CHOICES = (
        ("Pending", "Pending"),
        ("Done", "Done"),
    )

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    password = models.CharField(max_length=128)
    email_address = models.EmailField(unique=True, default="user@example.com")
    email_verified = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="Pending")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users"
        ordering = ["-created_at"]

    def __str__(self):
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email_address

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

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
