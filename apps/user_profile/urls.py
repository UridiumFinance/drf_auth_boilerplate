# apps/profiles/urls.py
from django.urls import path
from .views import (
    MyUserProfileView,
    DetailUserProfileView,
    GetMyMediaView,
    UploadMediaView,
)

app_name = "profiles"

urlpatterns = [
    # Perfil propio: GET (detalle) y PATCH (actualización parcial)
    path("me/", MyUserProfileView.as_view(), name="me"),

    # Perfil público por username (query param ?username=)
    path("detail/", DetailUserProfileView.as_view(), name="detail"),

    # Obtener signed URL de imagen de perfil o banner (?type=profile|banner)
    path("media/", GetMyMediaView.as_view(), name="media"),

    # Subir/registrar media y asignarlo a perfil (?type=profile|banner)
    path("upload/", UploadMediaView.as_view(), name="upload"),
]
