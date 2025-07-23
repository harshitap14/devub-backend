from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
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

    phone = models.CharField(max_length=15, blank=True, null=True)  # NEW
    address = models.TextField(blank=True, null=True)               # NEW
    # photo = models.ImageField(upload_to="admin_photos/", blank=True, null=True)  # NEW
    photo = models.TextField(blank=True, null=True)  # NEW

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
    
    # --- password helpers ---
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

