from rest_framework import serializers
from .models import Media
from utils.s3_utils import get_cloudfront_signed_url, normalize_ttl


class MediaSerializer(serializers.ModelSerializer):
    """
    Serializa Media y agrega `url` firmada.
    TTL por prioridad (mayor→menor):
      1) context["expire_seconds"]     # 👈 compat con tu ProductSerializer
      2) context["media_url_ttl"]      # opcional/alternativo
      3) settings.CLOUDFRONT_URL_TTL   # default global (o 60s)
    """
    url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Media
        fields = "__all__"   # si prefieres: enumera campos y deja `url` como read_only

    def get_url(self, obj: Media):
        # Lee primero 'expire_seconds' (lo que ya estás usando)
        ttl_ctx = (
            self.context.get("expire_seconds",
                self.context.get("media_url_ttl")   # fallback alternativo
            )
        )
        ttl = normalize_ttl(ttl_ctx)
        return get_cloudfront_signed_url(obj.key, expires_in=ttl)