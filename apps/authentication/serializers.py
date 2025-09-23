# apps/authentication/serializers.py
from typing import Optional

from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import serializers
from djoser.serializers import UserCreateSerializer as DjoserUserCreateSerializer

from apps.user_profile.models import UserProfile
from apps.assets.serializers import MediaSerializer
from utils.string_utils import (
    sanitize_string,
    sanitize_username,
    sanitize_email,
)

User = get_user_model()


# ---------------------------------------------------------------------
# Helper interno para obtener el UserProfile sin reventar en DoesNotExist
# y permitiendo usar un perfil ya prefetched vía context (para evitar N+1)
# ---------------------------------------------------------------------
def _get_user_profile(user, context) -> Optional[UserProfile]:
    """
    Si la vista hizo select_related/prefetch y guardó el perfil en el context
    (e.g., context["profile"] o context["profiles_map"][user.id]), úsalo.
    Si no, intenta una consulta única y maneja la ausencia con None.
    """
    # 1) Perfil directo en context (cuando serializas un solo usuario)
    ctx_profile = context.get("profile")
    if ctx_profile and getattr(ctx_profile, "user_id", None) == user.id:
        return ctx_profile

    # 2) Mapa de perfiles por id (cuando serializas listas)
    profiles_map = context.get("profiles_map")
    if isinstance(profiles_map, dict):
        prf = profiles_map.get(user.id)
        if prf:
            return prf

    # 3) Fallback: consulta directa (idealmente la vista debe usar select_related)
    try:
        return UserProfile.objects.select_related("profile_picture").get(user=user)
    except UserProfile.DoesNotExist:
        return None


# ==============================================================
# Create (Djoser) - campos explícitos, qr_code de solo lectura
# ==============================================================
class UserCreateSerializer(DjoserUserCreateSerializer):
    """
    Extiende el create de Djoser:
    - Campos explícitos (evitar "__all__")
    - Devuelve qr_code (firmado) como info de solo lectura
    """
    qr_code = serializers.SerializerMethodField(read_only=True)

    class Meta(DjoserUserCreateSerializer.Meta):
        model = User
        fields = (
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "password",
            "qr_code",  # read-only
        )
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate_email(self, value):
        # Normaliza + valida formato
        return sanitize_email(value)

    def validate_username(self, value):
        # Sanitiza y evita colisiones case-insensitive
        value = sanitize_username(value).lower()
        qs = User.objects.filter(username__iexact=value)
        if qs.exists():
            raise serializers.ValidationError("Este nombre de usuario ya está en uso.")
        # Evitar que parezca email
        if "@" in value:
            raise serializers.ValidationError("El nombre de usuario no puede ser un correo.")
        return value

    def validate_first_name(self, value):
        return sanitize_string(value)

    def validate_last_name(self, value):
        return sanitize_string(value)

    def get_qr_code(self, obj):
        """
        Devuelve el objeto Media serializado (solo lectura).
        Respetamos TTL si viene en context["expire_seconds"].
        """
        if obj.qr_code:
            return MediaSerializer(obj.qr_code, context=self.context).data
        return None


# ==============================================================
# Update parcial del usuario autenticado
# ==============================================================
class UpdateUserSerializer(serializers.ModelSerializer):
    """
    Serializer para actualizar datos básicos del usuario.
    Usa validaciones case-insensitive para email/username.
    """
    username   = serializers.CharField(required=False, max_length=100)
    first_name = serializers.CharField(required=False, max_length=100)
    last_name  = serializers.CharField(required=False, max_length=100)
    email      = serializers.CharField(required=False, max_length=150)

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email")

    def validate_username(self, value):
        value = sanitize_username(value).lower()
        # Excluir a uno mismo y chequear colisión case-insensitive
        qs = User.objects.exclude(pk=self.instance.pk).filter(username__iexact=value)
        if qs.exists():
            raise serializers.ValidationError("Este nombre de usuario ya está en uso.")
        if "@" in value:
            raise serializers.ValidationError("El nombre de usuario no puede ser un correo.")
        return value

    def validate_first_name(self, value):
        return sanitize_string(value)

    def validate_last_name(self, value):
        return sanitize_string(value)

    def validate_email(self, value):
        value = sanitize_email(value).lower()
        qs = User.objects.exclude(pk=self.instance.pk).filter(email__iexact=value)
        if qs.exists():
            raise serializers.ValidationError("Este correo ya está en uso.")
        return value


# ==============================================================
# User (privado) - incluye flags 2FA y URLs firmadas
# ==============================================================
class UserSerializer(serializers.ModelSerializer):
    """
    Detalle del usuario autenticado (privado).
    Devuelve:
      - qr_code (URL firmada, string)
      - profile_picture (URL firmada, string)
    """
    qr_code = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "username",
            "first_name",
            "last_name",
            "role",
            "verified",
            "updated_at",
            "two_factor_enabled",
            "otpauth_url",
            "login_otp",
            "login_otp_used",
            "otp_created_at",
            "qr_code",
            "profile_picture",
        ]

    def _media_url_or_none(self, media):
        if not media:
            return None
        # Respetar TTL via context["expire_seconds"] si existe
        return MediaSerializer(media, context=self.context).data.get("url")

    def get_profile_picture(self, obj):
        profile = _get_user_profile(obj, self.context)
        if profile and profile.profile_picture:
            return self._media_url_or_none(profile.profile_picture)
        return None

    def get_qr_code(self, obj):
        if obj.qr_code:
            return self._media_url_or_none(obj.qr_code)
        return None


# ==============================================================
# User (público) - datos no sensibles y media del perfil
# ==============================================================
class UserPublicSerializer(serializers.ModelSerializer):
    """
    Perfil público. Incluye:
      - profile_picture: objeto Media serializado (url firmada + metadatos)
    Nota: mantenemos este contrato "rico" porque tu código público ya lo
    consumía así (a diferencia del privado que usa solo la URL).
    """
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "username",
            "first_name",
            "last_name",
            "updated_at",
            "role",
            "verified",
            "profile_picture",
        ]

    def get_profile_picture(self, obj):
        profile = _get_user_profile(obj, self.context)
        if profile and profile.profile_picture:
            # Aquí devolvemos el objeto completo (no solo url) como ya usabas.
            return MediaSerializer(profile.profile_picture, context=self.context).data
        return None
