import uuid
from typing import Tuple

from django.conf import settings
from django.db import models, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.html import format_html

from ckeditor.fields import RichTextField

from apps.assets.models import Media

User = settings.AUTH_USER_MODEL


# -------------------------------
# Defaults centralizados
# -------------------------------
DEFAULT_PROFILE_KEY = "media/profiles/default/user_default_profile.png"
DEFAULT_PROFILE_NAME = "user_default_profile.png"
DEFAULT_PROFILE_MIME = "image/png"
DEFAULT_PROFILE_SIZE = 36500  # bytes aprox

DEFAULT_BANNER_KEY = "media/profiles/default/user_default_banner.jpg"
DEFAULT_BANNER_NAME = "user_default_banner.jpg"
DEFAULT_BANNER_MIME = "image/jpeg"
DEFAULT_BANNER_SIZE = 49900  # bytes aprox


class UserProfile(models.Model):
    """
    Perfil del usuario. Mantiene referencias a Media para fotos/baners,
    y metadatos públicos del usuario.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="profile"
    )

    profile_picture = models.ForeignKey(
        Media,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="as_profile_picture_of",
    )
    banner_picture = models.ForeignKey(
        Media,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="as_banner_picture_of",
    )

    # Si prefieres texto enriquecido:
    biography = RichTextField(blank=True, default="")
    birthday = models.DateField(blank=True, null=True)

    # Social / web
    website = models.URLField(blank=True, default="")
    instagram = models.URLField(blank=True, default="")
    facebook = models.URLField(blank=True, default="")
    threads = models.URLField(blank=True, default="")
    linkedin = models.URLField(blank=True, default="")
    youtube = models.URLField(blank=True, default="")
    tiktok = models.URLField(blank=True, default="")
    github = models.URLField(blank=True, default="")
    gitlab = models.URLField(blank=True, default="")

    def __str__(self) -> str:
        return f"Profile<{getattr(self.user, 'username', 'unknown')}>"

    # -------------------------------
    # Admin previews (sin serializer)
    # -------------------------------
    @property
    def _profile_pic_url(self):
        return self.profile_picture.get_signed_url() if self.profile_picture else None

    @property
    def _banner_pic_url(self):
        return self.banner_picture.get_signed_url() if self.banner_picture else None

    def profile_picture_preview(self):
        url = self._profile_pic_url
        if url:
            return format_html('<img src="{}" style="width:50px;height:auto;" />', url)
        return "—"

    def banner_picture_preview(self):
        url = self._banner_pic_url
        if url:
            return format_html('<img src="{}" style="width:50px;height:auto;" />', url)
        return "—"

    profile_picture_preview.short_description = "Profile Picture Preview"
    banner_picture_preview.short_description = "Banner Picture Preview"

    class Meta:
        indexes = [
            models.Index(fields=["birthday"]),
        ]
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


# -------------------------------
# Helpers para defaults
# -------------------------------
def _ensure_default_media(
    key: str, name: str, mime: str, size: int
) -> Media:
    """
    Obtiene o crea el Media por defecto. Idempotente.
    """
    obj, _created = Media.objects.get_or_create(
        key=key,
        defaults={
            "order": 0,
            "name": name,
            "size": size,          # asumiendo Media.size entero (refactor aplicado)
            "mime_type": mime,     # asumiendo Media.mime_type (refactor aplicado)
            "media_type": "image",
        },
    )
    return obj


# -------------------------------
# Señal: crear UserProfile con defaults
# -------------------------------
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, raw=False, **kwargs):
    """
    Crea el perfil y asigna imágenes por defecto al crear un usuario.
    - Protegido para no ejecutarse en cargas RAW de migraciones.
    - Idempotente (no duplica perfiles si el usuario existía).
    """
    if raw or not created:
        return

    with transaction.atomic():
        profile, _ = UserProfile.objects.get_or_create(user=instance)

        # Media por defecto (profile y banner). No fallamos si no existen, los creamos.
        profile_pic = _ensure_default_media(
            key=DEFAULT_PROFILE_KEY,
            name=DEFAULT_PROFILE_NAME,
            mime=DEFAULT_PROFILE_MIME,
            size=DEFAULT_PROFILE_SIZE,
        )
        banner_pic = _ensure_default_media(
            key=DEFAULT_BANNER_KEY,
            name=DEFAULT_BANNER_NAME,
            mime=DEFAULT_BANNER_MIME,
            size=DEFAULT_BANNER_SIZE,
        )

        # Solo asigna si no hay ya una imagen configurada
        updates = []
        if profile.profile_picture_id is None:
            profile.profile_picture = profile_pic
            updates.append("profile_picture")
        if profile.banner_picture_id is None:
            profile.banner_picture = banner_pic
            updates.append("banner_picture")

        if updates:
            profile.save(update_fields=updates)
