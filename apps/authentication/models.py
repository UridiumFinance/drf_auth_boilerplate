import uuid
from typing import Iterable, Optional

from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core import validators
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone

from apps.assets.models import Media
from utils.string_utils import (
    sanitize_username,
    sanitize_string,
    sanitize_email,   # lo usamos para normalizar adicionalmente
)

# -----------------------------
# Manager
# -----------------------------
class UserAccountManager(BaseUserManager):
    """
    User manager con:
    - email obligatorio, normalizado y lower-case
    - username opcional en create_user, validado/sanitizado si viene
    - nombres sanitizados
    - unicidad case-insensitive garantizada por constraints en Meta
    """
    RESTRICTED_USERNAMES = {"admin", "undefined", "null", "superuser", "root", "system"}

    def _clean_email(self, email: str) -> str:
        email = (email or "").strip().lower()
        # BaseUserManager.normalize_email preserva parte local;
        # igual reforzamos con nuestro sanitize_email (lanza ValidationError si inválido)
        email = self.normalize_email(email)
        email = sanitize_email(email)
        return email.lower()

    def _clean_username(self, username: Optional[str]) -> Optional[str]:
        if not username:
            return None
        username = sanitize_username(username).lower()
        if username in self.RESTRICTED_USERNAMES:
            raise ValueError(f"The username '{username}' is not allowed.")
        # evita que un "username" sea un email válido (confunde rutas / resoluciones)
        if "@" in username:
            raise ValueError("Username cannot be an email address.")
        return username

    def create_user(self, email: str, password: Optional[str] = None, **extra_fields):
        """
        Crea un usuario estándar. Si no hay password, marca unusable password.
        Usa constraints case-insensitive definidos en Meta para unicidad.
        """
        if not email:
            raise ValueError("Users must have an email address.")

        email = self._clean_email(email)

        username = extra_fields.pop("username", None)
        username = self._clean_username(username)

        # Sanitiza nombres (acepta None)
        first_name = sanitize_string(extra_fields.pop("first_name", "")) or ""
        last_name  = sanitize_string(extra_fields.pop("last_name", "")) or ""

        user = self.model(
            email=email,
            username=username or email.split("@")[0],  # fallback razonable
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        # full_clean para validar field validators y constraints antes del save
        user.full_clean(exclude=None)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str, **extra_fields):
        """
        Crea un superusuario. Password requerido.
        """
        if not password:
            raise ValueError("Superusers must have a password.")
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", "admin")

        user = self.create_user(email=email, password=password, **extra_fields)
        # En caso el caller haya sobreescrito flags, refuerza:
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.role = "admin"
        user.full_clean(exclude=None)
        user.save(using=self._db)
        return user


# -----------------------------
# Modelo principal
# -----------------------------
class UserAccount(AbstractBaseUser, PermissionsMixin):
    """
    Custom user con email como USERNAME_FIELD.
    Unicidad case-insensitive en email y username vía UniqueConstraint(Lower(...)).
    Campos para 2FA/TOTP/OTP login y QR (Media).
    """

    class Roles(models.TextChoices):
        CUSTOMER  = "customer",  "Customer"
        SELLER    = "seller",    "Seller"
        ADMIN     = "admin",     "Admin"
        MODERATOR = "moderator", "Moderator"
        HELPER    = "helper",    "Helper"
        EDITOR    = "editor",    "Editor"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Nota: EmailField valida formato. Usamos unicidad case-insensitive con constraint en Meta.
    email = models.EmailField(unique=True)
    # username con límites razonables; validator simple (solo letras, números, _ y -)
    username = models.CharField(
        max_length=100,
        unique=False,  # unique via Meta (LOWER)
        validators=[
            validators.RegexValidator(
                regex=r"^[a-zA-Z0-9_-]{3,100}$",
                message="Username must be 3-100 chars and contain only letters, numbers, underscores or hyphens.",
                code="invalid_username",
            )
        ],
    )

    first_name = models.CharField(max_length=100, blank=True, default="")
    last_name  = models.CharField(max_length=100, blank=True, default="")

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    role     = models.CharField(max_length=20, choices=Roles.choices, default=Roles.CUSTOMER)
    verified = models.BooleanField(default=False)

    is_active    = models.BooleanField(default=False)
    is_staff     = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # 2FA / TOTP (considera cifrar estos secretos en producción)
    two_factor_enabled = models.BooleanField(default=False)
    otpauth_url   = models.CharField(max_length=225, blank=True, null=True)
    otp_base32    = models.CharField(max_length=255, blank=True, null=True)
    otp_secret    = models.CharField(max_length=255, blank=True, null=True)
    otp_last_counter = models.BigIntegerField(blank=True, null=True)

    # QR como Media (mejor que ImageField si usas CloudFront/S3)
    qr_code = models.ForeignKey(
        Media,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="user_qr_codes",
    )

    # OTP login de un solo uso
    login_otp       = models.CharField(max_length=255, blank=True, null=True)
    login_otp_used  = models.BooleanField(default=False)
    otp_created_at  = models.DateTimeField(blank=True, null=True)

    # Auditoría básica
    login_ip = models.CharField(max_length=255, blank=True, null=True)

    objects = UserAccountManager()

    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    # -----------------------------
    # Métodos utilitarios
    # -----------------------------
    def __str__(self) -> str:
        # Evita exponer email completo si no quieres
        return self.username or self.email

    def get_full_name(self) -> str:
        return " ".join([self.first_name, self.last_name]).strip() or self.username

    def get_short_name(self) -> str:
        return self.first_name or self.username

    def get_qr_code(self) -> Optional[str]:
        """
        Devuelve una URL firmada si el QR está almacenado en Media con key.
        No accedemos a 'qr_code.url' (no existe en Media); usamos helper del modelo Media.
        """
        if self.qr_code:
            return self.qr_code.get_signed_url(expires_in=getattr(settings, "CLOUDFRONT_URL_TTL", 60))
        return None

    # -----------------------------
    # Normalizaciones a nivel de modelo
    # -----------------------------
    def clean(self):
        """
        Asegura normalización y sanitización antes de validaciones de DB.
        """
        super().clean()

        # normalizar/lower emails y usernames
        self.email = sanitize_email((self.email or "").strip().lower()).lower()
        # username puede venir vacío; si no viene deja que el manager calcule fallback
        if self.username:
            self.username = sanitize_username(self.username).lower()

        # nombres “seguros” (sin HTML ni caracteres raros)
        self.first_name = sanitize_string(self.first_name) or ""
        self.last_name  = sanitize_string(self.last_name) or ""

    def save(self, *args, **kwargs):
        # garantiza normalizaciones incluso si alguien hace .save() directo sin manager
        self.full_clean(exclude=None)
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

        # Unicidad case-insensitive en email y username
        constraints = [
            models.UniqueConstraint(
                Lower("email"),
                name="uniq_user_email_ci",
            ),
            models.UniqueConstraint(
                Lower("username"),
                name="uniq_user_username_ci",
            ),
        ]

        indexes = [
            models.Index(Lower("email"), name="idx_user_email_ci"),
            models.Index(Lower("username"), name="idx_user_username_ci"),
            models.Index(fields=["created_at"]),
            models.Index(fields=["login_ip"]),
        ]