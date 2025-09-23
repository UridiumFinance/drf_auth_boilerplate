from uuid import UUID
import re
from datetime import date

from django.utils.html import strip_tags
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from .models import UserProfile
from apps.assets.models import Media
from apps.assets.serializers import MediaSerializer

# -----------------------------
# Reglas auxiliares
# -----------------------------

URL_VALIDATOR = URLValidator(schemes=["https", "http"])  # http/https permitidos

DANGEROUS_SQL_TOKENS = re.compile(
    r"(--|;|/\*|\*/|xp_|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\b)",
    re.IGNORECASE,
)

HANDLE_REGEX = re.compile(r"^[A-Za-z0-9._-]{2,50}$")  # handles tipo @usuario (sin @)


def sanitize_text(value: str) -> str:
    """Quita HTML y espacios extra; uso defensivo para biografía corta."""
    value = strip_tags(value or "")
    return value.strip()


def validate_no_sqli(value: str, field_name: str):
    if not value:
        return
    if DANGEROUS_SQL_TOKENS.search(value):
        raise serializers.ValidationError({field_name: "Formato inválido."})


def validate_url_or_handle(value: str, field_name: str):
    """
    Acepta URL (http/https) o handle (A-Za-z0-9._-).
    """
    if not value:
        return
    validate_no_sqli(value, field_name)
    v = value.strip()
    if v.startswith(("http://", "https://")):
        try:
            URL_VALIDATOR(v)
        except DjangoValidationError:
            raise serializers.ValidationError({field_name: "URL inválida."})
    else:
        if not HANDLE_REGEX.match(v):
            raise serializers.ValidationError(
                {field_name: "Handle inválido. Usa letras, números, puntos, guiones y guiones bajos (2-50)."}
            )


def validate_https_url(value: str, field_name: str, allow_http: bool = True):
    if not value:
        return
    validate_no_sqli(value, field_name)
    v = value.strip()
    try:
        URL_VALIDATOR(v)
    except DjangoValidationError:
        raise serializers.ValidationError({field_name: "URL inválida."})
    if not allow_http and v.startswith("http://"):
        raise serializers.ValidationError({field_name: "Debe usar https."})


def resolve_media_or_none(media_id, user=None):
    """
    Resuelve un Media por UUID o None.
    Valida propiedad si el modelo Media tiene 'owner'.
    """
    if media_id in (None, "", 0):
        return None
    try:
        # Acepta str/UUID; normaliza a UUID si es str
        media_uuid = UUID(str(media_id))
    except Exception:
        raise serializers.ValidationError({"detail": "Media id debe ser un UUID válido."})

    try:
        media = Media.objects.get(pk=media_uuid)
    except Media.DoesNotExist:
        raise serializers.ValidationError({"detail": f"Media id {media_uuid} no existe."})

    if user and hasattr(media, "owner") and media.owner_id != user.id:
        raise serializers.ValidationError({"detail": "No tienes permiso para usar este media."})
    return media


# -----------------------------
# Serializer principal
# -----------------------------
class UserProfileSerializer(serializers.ModelSerializer):
    # Lectura (URLs firmadas, respetando TTL en context)
    profile_picture = serializers.SerializerMethodField(read_only=True)
    banner_picture = serializers.SerializerMethodField(read_only=True)

    # Escritura (IDs UUID)
    profile_picture_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)
    banner_picture_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)

    # Campos editables
    biography = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    birthday = serializers.DateField(required=False, allow_null=True)
    website = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    instagram = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    facebook = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    threads = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    linkedin = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    youtube = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    tiktok = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    github = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    gitlab = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = UserProfile
        fields = [
            # lectura (urls)
            "profile_picture",
            "banner_picture",
            # escritura (ids)
            "profile_picture_id",
            "banner_picture_id",
            # editables
            "biography",
            "birthday",
            "website",
            "instagram",
            "facebook",
            "threads",
            "linkedin",
            "youtube",
            "tiktok",
            "github",
            "gitlab",
        ]
        read_only_fields = ["profile_picture", "banner_picture"]

    # -----------------------------
    # Representación (lectura)
    # -----------------------------
    def _media_url(self, media_obj):
        if not media_obj:
            return None
        # Pasa self.context (incluye "expire_seconds" si la vista lo definió)
        return MediaSerializer(media_obj, context=self.context).data.get("url")

    def get_profile_picture(self, obj):
        return self._media_url(getattr(obj, "profile_picture", None))

    def get_banner_picture(self, obj):
        return self._media_url(getattr(obj, "banner_picture", None))

    # -----------------------------
    # Validaciones de campos
    # -----------------------------
    def validate_biography(self, value):
        v = sanitize_text(value)
        validate_no_sqli(v, "biography")
        if len(v) > 2000:
            raise serializers.ValidationError("Máximo 2000 caracteres.")
        return v

    def validate_birthday(self, value: date):
        if not value:
            return value
        today = timezone.now().date()
        if value > today:
            raise serializers.ValidationError("La fecha de nacimiento no puede ser futura.")
        if value.year < 1900:
            raise serializers.ValidationError("Fecha de nacimiento inválida.")
        return value

    def validate_website(self, value):
        if not value:
            return value
        validate_https_url(value, "website", allow_http=True)
        return value.strip()

    # Redes sociales: URL completa o handle
    def validate_instagram(self, value): validate_url_or_handle(value, "instagram"); return value and value.strip()
    def validate_facebook(self, value):  validate_url_or_handle(value, "facebook");  return value and value.strip()
    def validate_threads(self, value):    validate_url_or_handle(value, "threads");   return value and value.strip()
    def validate_linkedin(self, value):   validate_url_or_handle(value, "linkedin");  return value and value.strip()
    def validate_youtube(self, value):    validate_url_or_handle(value, "youtube");   return value and value.strip()
    def validate_tiktok(self, value):     validate_url_or_handle(value, "tiktok");    return value and value.strip()
    def validate_github(self, value):     validate_url_or_handle(value, "github");    return value and value.strip()
    def validate_gitlab(self, value):     validate_url_or_handle(value, "gitlab");    return value and value.strip()

    def validate(self, attrs):
        # Defensa en profundidad: límites de tamaño por campo string
        for k, v in list(attrs.items()):
            if isinstance(v, str) and len(v) > 5000:
                raise serializers.ValidationError({k: "Entrada demasiado larga."})
        return attrs

    # -----------------------------
    # create / update (transaccional)
    # -----------------------------
    @transaction.atomic
    def update(self, instance: UserProfile, validated_data):
        """
        Soporta partial_update.
        Maneja profile_picture_id / banner_picture_id como FKs a Media.
        Permite limpiar imágenes con null.
        """
        request = self.context.get("request")
        user = getattr(request, "user", None)

        pp_id = validated_data.pop("profile_picture_id", serializers.empty)
        bp_id = validated_data.pop("banner_picture_id", serializers.empty)

        if pp_id is not serializers.empty:
            instance.profile_picture = resolve_media_or_none(pp_id, user=user)

        if bp_id is not serializers.empty:
            instance.banner_picture = resolve_media_or_none(bp_id, user=user)

        # Asignar campos presentes
        for field in [
            "biography", "birthday", "website", "instagram", "facebook",
            "threads", "linkedin", "youtube", "tiktok", "github", "gitlab",
        ]:
            if field in validated_data:
                setattr(instance, field, validated_data[field])

        # Guardar solo los campos modificados (eficiente)
        instance.save(update_fields=[
            f for f in [
                "profile_picture" if pp_id is not serializers.empty else None,
                "banner_picture" if bp_id is not serializers.empty else None,
                *validated_data.keys(),
            ] if f
        ])
        return instance

    @transaction.atomic
    def create(self, validated_data):
        """
        Permite crear el perfil estableciendo medias por ID si se envían.
        """
        request = self.context.get("request")
        user = getattr(request, "user", None)

        pp_id = validated_data.pop("profile_picture_id", None)
        bp_id = validated_data.pop("banner_picture_id", None)

        instance = UserProfile.objects.create(**validated_data)

        if pp_id is not None:
            instance.profile_picture = resolve_media_or_none(pp_id, user=user)
        if bp_id is not None:
            instance.banner_picture = resolve_media_or_none(bp_id, user=user)

        if pp_id is not None or bp_id is not None:
            instance.save(update_fields=["profile_picture", "banner_picture"])
        return instance
