from datetime import timedelta
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth import get_user_model

from rest_framework import permissions, status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework_api.views import StandardAPIView

from botocore.signers import CloudFrontSigner

from core.permissions import HasValidAPIKey
from apps.assets.models import Media
from apps.authentication.serializers import UserPublicSerializer
from .models import UserProfile
from .serializers import UserProfileSerializer
from utils.s3_utils import rsa_signer

User = get_user_model()

# ------------------------
# Utilidad: firmar URL
# ------------------------
def get_signed_url(key: str, expire_seconds: int = 60) -> str:
    """Genera un signed URL para un objeto en CloudFront."""
    if not key:
        return None
    key_id = settings.AWS_CLOUDFRONT_KEY_ID
    signer = CloudFrontSigner(key_id, rsa_signer)
    expire_date = timezone.now() + timedelta(seconds=expire_seconds)
    obj_url = f"https://{settings.AWS_CLOUDFRONT_DOMAIN}/{key}"
    return signer.generate_presigned_url(obj_url, date_less_than=expire_date)


# ------------------------
# Perfil propio
# ------------------------
class MyUserProfileView(RetrieveUpdateAPIView):
    """
    GET: Obtener mi perfil
    PATCH: Actualizar campos del perfil
    """
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return UserProfile.objects.select_related("profile_picture", "banner_picture").get(user=self.request.user)


# ------------------------
# Perfil público (por username)
# ------------------------
class DetailUserProfileView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def get(self, request):
        username = request.query_params.get("username")
        if not username:
            return self.response("A valid username must be provided", status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return self.response("User does not exist", status=status.HTTP_404_NOT_FOUND)

        profile = UserProfile.objects.get(user=user)
        return self.response({
            "user": UserPublicSerializer(user).data,
            "profile": UserProfileSerializer(profile).data,
        })


# ------------------------
# Foto/Banner (firmado)
# ------------------------
class GetMyMediaView(StandardAPIView):
    """
    GET /api/profile/media/?type=profile|banner
    Devuelve una signed URL de la imagen
    """
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        media_type = request.query_params.get("type")
        profile = UserProfile.objects.get(user=request.user)

        if media_type == "profile":
            media = profile.profile_picture
        elif media_type == "banner":
            media = profile.banner_picture
        else:
            return self.response("Invalid media type", status=status.HTTP_400_BAD_REQUEST)

        if not media or not media.key:
            return self.response(f"No {media_type} picture found.", status=status.HTTP_404_NOT_FOUND)

        return self.response(get_signed_url(media.key))


# ------------------------
# Subida de media
# ------------------------
class UploadMediaView(StandardAPIView):
    """
    POST /api/profile/upload/?type=profile|banner
    Guarda un Media y lo asigna al perfil
    """
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        media_type = request.query_params.get("type")
        profile = UserProfile.objects.get(user=request.user)

        key = request.data.get("key")
        title = request.data.get("title")
        size = request.data.get("size")
        file_type = request.data.get("type")

        if not all([key, title, size, file_type]):
            return self.response("Missing fields.", status=status.HTTP_400_BAD_REQUEST)

        media = Media.objects.create(
            owner=request.user,
            order=0,
            name=title,
            size=size,
            type=file_type,
            key=key,
            media_type="image",
        )

        if media_type == "profile":
            profile.profile_picture = media
        elif media_type == "banner":
            profile.banner_picture = media
        else:
            return self.response("Invalid media type", status=status.HTTP_400_BAD_REQUEST)

        profile.save(update_fields=["profile_picture", "banner_picture"])
        return self.response(f"{media_type.capitalize()} picture has been updated.")