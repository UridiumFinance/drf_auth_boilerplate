from django.contrib import admin

from .models import Media
from .forms import MediaAdminForm


def _mime_field_name() -> str:
    # Soporta ambos esquemas: el viejo 'type' o el nuevo 'mime_type'
    return "mime_type" if hasattr(Media, "mime_type") else "type"


@admin.register(Media)
class MediaAdmin(admin.ModelAdmin):
    form = MediaAdminForm

    list_display = ["name", "image_preview", "media_type", "key"]
    list_filter = ["media_type"]
    search_fields = ["name", "key"] + ([_mime_field_name()] if _mime_field_name() else [])

    # Hacemos los readonly_fields dinámicos para evitar admin.E035
    def get_readonly_fields(self, request, obj=None):
        return ["image_display", "name", "size", _mime_field_name(), "key"]

    # También ajustamos los fieldsets para usar el campo correcto
    def get_fieldsets(self, request, obj=None):
        mime_field = _mime_field_name()
        return (
            ("Subir archivo", {
                "fields": ("file", "s3_path", "media_type", "order")
            }),
            ("Vista previa", {
                "fields": ("image_display",)
            }),
            ("Metadatos (auto-llenado)", {
                "fields": ("name", "size", mime_field, "key")
            }),
        )

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super().get_search_results(request, queryset, search_term)
        # Limitar solo a imágenes si lo quieres así
        queryset = queryset.filter(media_type="image")
        return queryset, use_distinct
