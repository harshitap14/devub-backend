import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-please-change")
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    # Django core
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party
    "rest_framework",
    "rest_framework.authtoken",
    "drf_yasg",

    # Local
    "devhubapp",
    "corsheaders",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
CORS_ALLOWED_ORIGINS = [
    "https://d0812bg9-8000.inc1.devtunnels.ms",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True


ROOT_URLCONF = "devhub.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "devhub.wsgi.application"
ASGI_APPLICATION = "devhub.asgi.application"

# --- PostgreSQL ---
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'USER': 'postgres.plpmyfzzbnwjbwkxiymd',
        'PASSWORD': 'gleecus1234@',  # Replace with your actual password
        'HOST': 'aws-0-ap-south-1.pooler.supabase.com',
        'PORT': '6543',
        
    }
}


# --- Authentication Backends ---
AUTHENTICATION_BACKENDS = [
    "devhubapp.backends.EmailBackend",   # email-first auth
    "django.contrib.auth.backends.ModelBackend",  # fallback username
]

# --- DRF ---
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    'AUTH_USER_MODEL': 'devhubapp.AppUser',
}

# --- Email (Gmail SMTP) ---
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "devcards631@gmail.com")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "bkcp bwig frtm akgx")  # Consider App Password
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# Frontend URL that will receive reset links (change in env as needed)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000/auth/v1")

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://d0812bg9-8000.inc1.devtunnels.ms",
]
#MEDIA_URL = "/media/"
#MEDIA_ROOT = BASE_DIR / "media"

# settings.py
AUTH_USER_MODEL = "devhubapp.AppUser"


# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SUPABASE_S3_ENDPOINT = "https://plpmyfzzbnwjbwkxiymd.supabase.co/storage/v1/s3"
SUPABASE_S3_REGION = "ap-south-1"
SUPABASE_BUCKET = "admin-photos"  
SUPABASE_ACCESS_KEY = "0657c2617166a17418b662b3b379e84d"
SUPABASE_SECRET_KEY = "2a757e52487be628691979badfb4a61cf9978eafb5f5006e590e9127e24a1e34"

# WorkOS Settings
WORKOS_API_KEY = "sk_test_a2V5XzAxSllLSkE0U0pYNFg1WFBTSE4yRFdUVkhZLFVsYnMwZFFBNE1LVElsTTlxeThIOFlHaDY"
WORKOS_CLIENT_ID = "client_01JYKJA5EEXMYRTHKZVN3ZQJCB"
WORKOS_REDIRECT_URI = "http://localhost:8000/callback/"
WORKOS_ORGANIZATION_ID = "org_01JYRQXPG1SQGN0MRHEY994GH2"
