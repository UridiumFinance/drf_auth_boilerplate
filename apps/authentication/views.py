from io import BytesIO
import logging

from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.contrib.auth.hashers import make_password
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import get_random_string

from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_api.views import StandardAPIView

import pyotp
import qrcode

from core.permissions import HasValidAPIKey
from core.storage_backends import PublicMediaStorage

from utils.ip_utils import get_client_ip
from utils.s3_utils import normalize_ttl
from utils.string_utils import sanitize_email

from apps.assets.models import Media
from apps.assets.serializers import MediaSerializer

from .serializers import UpdateUserSerializer
from utils.otp_utils import (
    _check_rate_limit,
    _totp_for_user,
    _otp_expires_in_seconds,
    _get_from_email,
    _register_send,
    _verify_and_get_counter,
)

User = get_user_model()
logger = logging.getLogger(__name__)

# Config TOTPs (ajusta según UX/seguridad)
TOTP_INTERVAL = 300       # segundos por paso (p.ej. 30, 60, 300)
TOTP_VALID_WINDOW = 1     # tolerancia ± ventanas


# ---------------------------------------------------------------------
# Helpers locales (DRY)
# ---------------------------------------------------------------------
def _active_user_by_email_ci(email: str):
    """
    Busca usuario activo por email (case-insensitive).
    Devuelve None si no existe.
    """
    if not email:
        return None
    return User.objects.filter(email__iexact=email.strip().lower(), is_active=True).first()


def _require_2fa_enrolled(user: User):
    """
    Chequea que el usuario tenga registro de 2FA (qr_code y otp_base32).
    Devuelve (ok, msg) para control de flujo simple en vistas.
    """
    if not getattr(user, "qr_code", None) or not getattr(user, "otp_base32", None):
        return False, "QR Code or OTP Base32 not found for user"
    return True, ""


def _media_ttl_from_request(request):
    """
    TTL para firmar media, opcionalmente por query param ?ttl=..
    Se normaliza a límites seguros en utils.s3_utils.normalize_ttl.
    """
    raw = request.query_params.get("ttl")
    return normalize_ttl(raw) if raw is not None else None


# ---------------------------------------------------------------------
# Actualizar usuario autenticado
# ---------------------------------------------------------------------
class UpdateUserInformationView(StandardAPIView):
    """
    PUT/PATCH /api/users/me/
    Actualiza username, first_name, last_name y/o email.
    Usa UpdateUserSerializer (valida case-insensitive duplicados y sanitiza).
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]
    serializer_class = UpdateUserSerializer

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(serializer.data, status=status.HTTP_200_OK)

    # También aceptamos PATCH por ergonomía (parcial)
    def patch(self, request, *args, **kwargs):
        return self.put(request, *args, **kwargs)


# ---------------------------------------------------------------------
# Generar QR & registrar secreto TOTP para 2FA
# ---------------------------------------------------------------------
class GenerateQRCodeView(StandardAPIView):
    """
    GET /api/users/2fa/qrcode/
    Genera un secreto TOTP (base32) y un QR (Media) para apps de autenticación.
    No activa 2FA automáticamente; eso lo hace Set2FAView.
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def get(self, request):
        user = request.user
        email = (user.email or "").lower()

        # 1) Generar secreto y URL provisioning estándar (otpauth://)
        otp_base32 = pyotp.random_base32()
        issuer = Site.objects.get_current().name or "SoloPython"
        otp_auth_url = pyotp.totp.TOTP(otp_base32, interval=TOTP_INTERVAL).provisioning_uri(
            name=email, issuer_name=issuer
        )

        # 2) Renderizar QR en memoria
        stream = BytesIO()
        qrcode.make(otp_auth_url).save(stream)
        content_file = ContentFile(stream.getvalue())

        # 3) Subir a S3 (PublicMediaStorage maneja la ruta base p.ej. "media/")
        storage = PublicMediaStorage()
        qr_code_name = f"qr_{get_random_string(10)}.png"
        storage_key = f"qrcode/{qr_code_name}"              # clave relativa dentro del storage
        storage.save(storage_key, content_file)

        # 4) Crear objeto Media (usar campos consolidados: size numérico, mime_type)
        media = Media.objects.create(
            owner=user,
            order=0,
            name=qr_code_name,
            size=content_file.size,
            mime_type="image/png",
            key=f"media/{storage_key}",   # si tu CDN sirve desde "media/", ajusta según tu backend
            media_type="image",
        )

        # 5) Guardar referencias en el usuario (NO activamos 2FA aún)
        user.otp_base32 = otp_base32
        user.otpauth_url = otp_auth_url
        user.qr_code = media
        user.save(update_fields=["otp_base32", "otpauth_url", "qr_code"])

        # 6) Responder con MediaSerializer y TTL configurable (?ttl=..)
        ctx = {"request": request}
        ttl = _media_ttl_from_request(request)
        if ttl is not None:
            ctx["expire_seconds"] = ttl
        return self.response(MediaSerializer(media, context=ctx).data, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------
# Reset OTP (login OTP único) – envía/actualiza contraseñas de un solo uso
# ---------------------------------------------------------------------
class OTPLoginResetView(StandardAPIView):
    """
    POST /api/users/otp/reset/
    Genera y almacena un OTP derivado del TOTP actual (hash), para flujos que
    quieran comparar server-side sin exponer secreto. (Opcional según tu UX)
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        user = request.user

        # Registrar IP (y alertar si cambia)
        new_ip = get_client_ip(request)
        if user.login_ip and user.login_ip != new_ip:
            logger.info("New login IP detected for user %s (old=%s new=%s)", user.email, user.login_ip, new_ip)
            # TODO: enviar correo de alerta
        user.login_ip = new_ip

        ok, msg = _require_2fa_enrolled(user)
        if not ok:
            return self.error(msg)

        try:
            totp = pyotp.TOTP(user.otp_base32, interval=TOTP_INTERVAL)
            otp_now = totp.now()
        except Exception:
            return self.error("Error generating OTP.")

        # Guardamos hash + metadatos anti-reuso
        user.login_otp = make_password(otp_now)
        user.otp_created_at = timezone.now()
        user.login_otp_used = False
        user.save(update_fields=["login_otp", "otp_created_at", "login_otp_used", "login_ip"])

        return self.response("OTP Reset Successfully for user")


# ---------------------------------------------------------------------
# Verificar TOTP en sesión autenticada (2FA flows)
# ---------------------------------------------------------------------
class VerifyOTPView(StandardAPIView):
    """
    POST /api/users/otp/verify/
    Verifica un TOTP contra el secreto base32 del usuario autenticado.
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        user = request.user
        ok, msg = _require_2fa_enrolled(user)
        if not ok:
            return self.error(msg)

        otp = str(request.data.get("otp", "")).strip()
        totp = pyotp.TOTP(user.otp_base32, interval=TOTP_INTERVAL)

        if totp.verify(otp, valid_window=TOTP_VALID_WINDOW):
            user.login_otp_used = True
            user.save(update_fields=["login_otp_used"])
            return self.response("OTP Verified")
        return self.error("Error Verifying One Time Password")


# ---------------------------------------------------------------------
# Desactivar 2FA
# ---------------------------------------------------------------------
class DisableOTPView(StandardAPIView):
    """
    POST /api/users/2fa/disable/
    Exige OTP válido y elimina artefactos de 2FA.
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        user = request.user
        ok, msg = _require_2fa_enrolled(user)
        if not ok:
            return self.error(msg)

        otp = str(request.data.get("otp", "")).strip()
        totp = pyotp.TOTP(user.otp_base32, interval=TOTP_INTERVAL)

        if not totp.verify(otp, valid_window=TOTP_VALID_WINDOW):
            return self.error("Error Verifying One Time Password")

        # Limpiar artefactos de 2FA
        user.two_factor_enabled = False
        user.otpauth_url = None
        user.otp_base32 = None
        user.qr_code = None
        user.login_otp = None
        user.login_otp_used = False
        user.otp_created_at = None
        user.save(update_fields=[
            "two_factor_enabled", "otpauth_url", "otp_base32", "qr_code",
            "login_otp", "login_otp_used", "otp_created_at"
        ])

        return self.response("Two Factor Authentication Disabled")


# ---------------------------------------------------------------------
# Activar/Desactivar flag 2FA (requiere QR ya generado)
# ---------------------------------------------------------------------
class Set2FAView(StandardAPIView):
    """
    POST /api/users/2fa/set/
    Body: {"bool": true|false}
    Activa/Desactiva el flag two_factor_enabled.
    No genera QR ni valida OTP aquí (eso es tarea de GenerateQRCode/VerifyOTP).
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request, *args, **kwargs):
        user = request.user
        if user.qr_code is None:
            return self.error("QR Code not found for the user.")

        enabled = bool(request.data.get("bool"))
        user.two_factor_enabled = enabled
        user.save(update_fields=["two_factor_enabled"])

        return self.response("2FA Activated" if enabled else "2FA Disabled")


# ---------------------------------------------------------------------
# OTP login por email (no autenticado) – enviar y verificar
# ---------------------------------------------------------------------
class SendOTPLoginView(StandardAPIView):
    """
    POST /api/auth/otp/send/
    Body: {"email": "..."}
    Envía un código OTP TOTP por correo, con rate limit básico.
    """
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        # Sanitiza email antes de usarlo
        email = sanitize_email((request.data.get("email") or "").strip().lower())
        if not email:
            return self.error("Email is required.")

        user = _active_user_by_email_ci(email)
        if not user:
            # Opcional: no revelar existencia
            # return self.response("If the account exists, an OTP has been sent.")
            return self.error("User does not exist or is not active.")

        # Rate limit (por usuario)
        ok, msg = _check_rate_limit(user)
        if not ok:
            return self.error(msg)

        # Secreto estable por usuario
        if not getattr(user, "otp_secret", None):
            user.otp_secret = pyotp.random_base32()
            user.save(update_fields=["otp_secret"])

        totp = _totp_for_user(user)     # respeta TOTP_INTERVAL internamente
        otp = totp.now()
        expires_in = _otp_expires_in_seconds()

        try:
            from_email = _get_from_email(request)
            send_mail(
                subject="Your OTP Code",
                message=f"Your OTP code is {otp}\nIt expires in ~{expires_in}s.",
                from_email=from_email,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception:
            logger.exception("SMTP failure while sending OTP to %s", user.email)
            return self.error("Failed to send OTP. Please try again in a moment.")

        _register_send(user)

        return self.response({"message": "OTP sent successfully.", "expires_in": expires_in})


class VerifyOTPLoginView(StandardAPIView):
    """
    POST /api/auth/otp/verify/
    Body: {"email": "...", "otp": "..."}
    Verifica TOTP contra otp_secret del usuario y emite tokens JWT.
    Protegido contra reuso por contador (otp_last_counter).
    """
    permission_classes = [HasValidAPIKey]

    @transaction.atomic
    def post(self, request):
        email = sanitize_email((request.data.get("email") or "").strip().lower())
        otp_code = str((request.data.get("otp") or "")).strip()

        if not email or not otp_code:
            return self.error("Both email and OTP code are required.")

        user = User.objects.filter(email__iexact=email, is_active=True).select_for_update().first()
        if not user:
            return self.error("User does not exist or is not active.")

        if not getattr(user, "otp_secret", None):
            return self.error("No OTP secret registered for this user.")

        totp = _totp_for_user(user)  # usa mismo intervalo que el envío
        now = timezone.now()

        # Verificación y anti-reuso
        candidate_counter = _verify_and_get_counter(totp, otp_code, now, valid_window=TOTP_VALID_WINDOW)
        if candidate_counter is None:
            return self.error("Invalid or expired OTP.")

        last_counter = getattr(user, "otp_last_counter", None)
        if last_counter is not None and candidate_counter <= last_counter:
            return self.error("OTP already used or too old.")

        user.otp_last_counter = candidate_counter
        user.save(update_fields=["otp_last_counter"])

        # Éxito: emitir tokens
        refresh = RefreshToken.for_user(user)
        return self.response({"access": str(refresh.access_token), "refresh": str(refresh)})