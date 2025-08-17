"""
Django settings for project.

✅ Default: pohodlný DEV režim (běží bez env proměnných)
   - DEBUG=True
   - SECRET_KEY je zadrátovaný (lze přepsat DJANGO_SECRET_KEY)
   - ALLOWED_HOSTS = ["*"]
   - Ověřování URL v UI povoleno (ALLOW_EXTERNAL_VERIFY_URLS=1)

🔐 Optional PROD (přes env):
   - DJANGO_DEBUG=0
   - DJANGO_SECRET_KEY=... (povinné v prod)
   - DJANGO_ALLOWED_HOSTS="example.com,www.example.com"
   - DJANGO_CSRF_TRUSTED="https://example.com,https://www.example.com"
   - ALLOW_EXTERNAL_VERIFY_URLS=0 (doporučeno v prod)
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# -----------------------------
# ZÁKLAD
# -----------------------------
# DEV defaulty:
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"

# SECRET_KEY: v DEV necháváme vygenerovaný; v PROD přepiš DJANGO_SECRET_KEY
SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "django-insecure-z)j^oy-mef0rj_)6^&_5hp&an)65*+@ndg2ok6#ke%higd4apg",
)

# V DEV povolíme všechny hosty; v PROD nastav DJANGO_ALLOWED_HOSTS
if DEBUG:
    ALLOWED_HOSTS = ["*"]
else:
    ALLOWED_HOSTS = [h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",") if h.strip()]

CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.getenv("DJANGO_CSRF_TRUSTED", "").split(",") if o.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "los",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# DŮLEŽITÉ: route projektu
ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
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

WSGI_APPLICATION = "project.wsgi.application"

# -----------------------------
# DB (SQLite pro DEV)
# -----------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# -----------------------------
# HESLA
# -----------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# -----------------------------
# I18N / ČAS
# -----------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# -----------------------------
# STATIKA
# -----------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"  # pro collectstatic v PROD

# -----------------------------
# SECURITY – zapíná se v PROD
# -----------------------------
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # HSTS (aktivuj, jakmile máš plně HTTPS)
    SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

    # Reverse proxy (nginx/traefik)
    if os.getenv("DJANGO_BEHIND_PROXY", "1") == "1":
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# -----------------------------
# APLIKAČNÍ NASTAVENÍ (UI ověřování URL)
# DEV default: povoleno; v PROD doporučuji vypnout (ALLOW_EXTERNAL_VERIFY_URLS=0)
# -----------------------------
ALLOW_EXTERNAL_VERIFY_URLS = os.getenv("ALLOW_EXTERNAL_VERIFY_URLS", "1") == "1"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

