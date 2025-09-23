import uuid
from typing import Optional

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.html import format_html
from django.contrib import admin
from django.core.exceptions import ValidationError

from utils.s3_utils import get_cloudfront_signed_url


class Media(models.Model):
    """
    Representa un archivo subido y direccionable vía CloudFront/S3.
    Puede usarse para imágenes de perfil, banners, documentos, etc.
    """
    class Types(models.TextChoices):
        IMAGE = "image", "Image"
        VIDEO = "video", "Video"
        DOCUMENT = "document", "Document"
        AUDIO = "audio", "Audio"
    
    class MimeType(models.TextChoices):
        # Imágenes
        IMAGE_JPEG = "image/jpeg", "JPEG"
        IMAGE_PNG = "image/png", "PNG"
        IMAGE_WEBP = "image/webp", "WEBP"
        IMAGE_GIF = "image/gif", "GIF"
        IMAGE_SVG = "image/svg+xml", "SVG"

        # Video
        VIDEO_MP4 = "video/mp4", "MP4"
        VIDEO_WEBM = "video/webm", "WEBM"
        VIDEO_QUICKTIME = "video/quicktime", "QuickTime (.mov)"

        # Audio
        AUDIO_MPEG = "audio/mpeg", "MP3"
        AUDIO_WAV  = "audio/wav", "WAV"
        AUDIO_OGG  = "audio/ogg", "OGG"

        # Documentos / texto / datos
        APPLICATION_PDF  = "application/pdf", "PDF"
        TEXT_PLAIN       = "text/plain", "Texto"
        TEXT_CSV         = "text/csv", "CSV"
        APPLICATION_JSON = "application/json", "JSON"
        APPLICATION_ZIP  = "application/zip", "ZIP"
        # Office comunes (opcional)
        APPLICATION_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "DOCX"
        APPLICATION_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "XLSX"

        # Fallback genérico
        APPLICATION_OCTET = "application/octet-stream", "Binario/Otro"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Orden relativo (útil para galerías)
    order = models.PositiveIntegerField(default=0)

    # Metadata básica
    name = models.CharField(max_length=256)
    # Tamaño del archivo en bytes
    size = models.PositiveBigIntegerField(default=0)
    # MIME type (p.ej. image/png, application/pdf)
    mime_type = models.CharField(
        max_length=128,
        choices=MimeType.choices,
        default=MimeType.APPLICATION_OCTET,
        db_index=True,
    )
    # Clave/objeto en el bucket (p.ej. "uploads/2025/09/abc123.png")
    key = models.CharField(max_length=512, unique=True, db_index=True)

    # Clasificación funcional
    media_type = models.CharField(max_length=30, choices=Types.choices)

    # Propietario (opcional, pero recomendado para permisos)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="media_items",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    # Auditoría
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    # -----------------------------
    # Métodos de ayuda / presentación
    # -----------------------------
    def __str__(self) -> str:
        return self.name or str(self.id)

    def get_signed_url(self, expires_in: int = 60) -> Optional[str]:
        """
        Devuelve una URL firmada de CloudFront para la key.
        """
        if not self.key:
            return None
        return get_cloudfront_signed_url(self.key, expires_in=expires_in)
    
    @property
    def is_image(self) -> bool:
        return (self.mime_type or "").startswith("image/")

    @property
    def is_video(self) -> bool:
        return (self.mime_type or "").startswith("video/")

    @property
    def is_audio(self) -> bool:
        return (self.mime_type or "").startswith("audio/")
    
    # (Opcional) Valida coherencia entre media_type y mime_type
    def clean(self):
        super().clean()
        if self.media_type == self.Types.IMAGE and not self.is_image:
            raise ValidationError({"mime_type": "mime_type debe ser de tipo image/* para media_type=image."})
        if self.media_type == self.Types.VIDEO and not self.is_video:
            raise ValidationError({"mime_type": "mime_type debe ser de tipo video/* para media_type=video."})
        if self.media_type == self.Types.AUDIO and not self.is_audio:
            raise ValidationError({"mime_type": "mime_type debe ser de tipo audio/* para media_type=audio."})


    @admin.display(description="Preview")
    def image_preview(self):
        """
        Vista miniatura para el admin.
        Solo aplica a media_type=image y si hay key.
        """
        if self.media_type == self.Types.IMAGE and self.key:
            url = self.get_signed_url(expires_in=60)
            if url:
                return format_html('<img src="{}" style="width:60px;height:auto;" />', url)
            return "—"
        return "—"

    @admin.display(description="Vista previa")
    def image_display(self):
        """
        Vista grande para el admin (detalle).
        """
        if self.media_type == self.Types.IMAGE and self.key:
            url = self.get_signed_url(expires_in=120)
            if url:
                return format_html(
                    '<img src="{}" style="max-width:300px;height:auto;border:1px solid #ccc;" />',
                    url
                )
            return "—"
        return "—"

    class Meta:
        indexes = [
            models.Index(fields=["media_type"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["order", "-created_at"]
