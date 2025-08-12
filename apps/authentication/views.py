from io import BytesIO

from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework import status
from rest_framework import permissions
from rest_framework_api.views import StandardAPIView

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.files.base import ContentFile
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.utils.timezone import now
from django.core.mail import send_mail
from django.contrib.sites.models import Site

import pyotp
import time
import qrcode

from core.storage_backends import PublicMediaStorage
from core.permissions import HasValidAPIKey
from utils.ip_utils import get_client_ip
from apps.assets.models import Media
from apps.assets.serializers import MediaSerializer
from .serializers import UpdateUserSerializer

User = get_user_model()

TOTP_INTERVAL = 300        # 30–120s según UX
TOTP_VALID_WINDOW = 1     # acepta ±1 ventana

class UpdateUserInformationView(StandardAPIView):
    """
    PUT /api/users/me/
    Permite al usuario autenticado actualizar username, first_name y last_name.
    """

    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]
    serializer_class   = UpdateUserSerializer

    def put(self, request, *args, **kwargs):
        user = request.user
        # partial=True permite enviar sólo subset de campos
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(serializer.data, status=status.HTTP_200_OK)
    

class GenerateQRCodeView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def get(self,request):
        user = request.user
        email = user.email

        otp_base32 = pyotp.random_base32()
        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="SoloPython"
        )

        stream = BytesIO()
        image = qrcode.make(f"{otp_auth_url}")
        image.save(stream)

        # Nombre con ruta completa
        qr_code_name = f"qr{get_random_string(10)}.png"
        content_file = ContentFile(stream.getvalue())

        # Subir a S3
        storage = PublicMediaStorage()
        storage.save(f"qrcode/{qr_code_name}", content_file)

        # Crear objeto Media
        media = Media.objects.create(
            name=qr_code_name,
            size=f"{content_file.size} bytes",
            type="png",
            key=f"media/qrcode/{qr_code_name}",
            media_type="image",
        )

        # Guardar en el usuario
        user.otp_base32 = otp_base32
        user.otpauth_url = otp_auth_url
        user.qr_code = media
        user.save()

        serialized_qr_code = MediaSerializer(media).data
        return self.response(serialized_qr_code)
    

class OTPLoginResetView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        user = request.user

        new_ip = get_client_ip(request)

        if user.login_ip and user.login_ip != new_ip:
            print(f"New login IP for user: {user.email}")
            # TODO: Send user email

        user.login_ip = new_ip

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")
        
        try:
            totp = pyotp.TOTP(user.otp_base32).now()
        except Exception as e:
            return self.error(f"Error generating TOPT: {str(e)}")
        
        user.login_otp = make_password(totp)
        user.otp_created_at = timezone.now()
        user.login_otp_used = False

        user.save()

        return self.response("OTP Reset Successfully for user")


class VerifyOTPView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self,request):
        user = request.user

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")

        # Get TOTP
        totp = pyotp.TOTP(user.otp_base32)
        otp = request.data.get("otp")
        verified = totp.verify(otp)

        if verified:
            user.login_otp_used = True
            user.save()
            return self.response("OTP Verified")
        else:
            return self.error("Error Verifying One Time Password")
        

class DisableOTPView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self,request):
        user = request.user

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")
        
        # Get TOTP
        totp = pyotp.TOTP(user.otp_base32)
        otp = request.data.get("otp")
        verified = totp.verify(otp)

        if verified:
            user.two_factor_enabled = False
            user.otpauth_url = None
            user.otp_base32 = None
            user.qr_code = None
            user.login_otp = None
            user.login_otp_used = False
            user.otp_created_at = None
            user.save()

            return self.response("Two Factor Authentication Disabled")
        else:
            return self.error("Error Verifying One Time Password")
        

class Set2FAView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request, *args, **kwargs):
        user = request.user

        if user.qr_code is None:
            return self.error(
                "QR Code not found for the user."
            )

        boolean = bool(request.data.get("bool"))

        if boolean:
            user.two_factor_enabled = True
            user.save()
            return self.response("2FA Activated")
        else:
            user.two_factor_enabled = False
            user.save()
            return self.response("2FA Disabled")
        

class OTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp')

        if not email or not otp_code:
            return self.error("Both email and OTP code are required.")

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return self.error("User does not exist or is not active.", status=status.HTTP_404_NOT_FOUND)

        # Verifica con el mismo secreto usado en SendOTPLoginView
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp_code, valid_window=1):
            return self.error("Invalid or expired OTP code.")

        # Marcar OTP como usado si lo deseas, o generar uno nuevo
        refresh = RefreshToken.for_user(user)
        return self.response({
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        })
        
        
class SendOTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return self.error("Email is required.")

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return self.error("User does not exist or is not active.")

        # Crear el secreto SOLO si no existe (secreto estable por usuario)
        if not getattr(user, "otp_secret", None):
            user.otp_secret = pyotp.random_base32()
            user.save(update_fields=["otp_secret"])

        # Generar OTP para el momento actual (aware)
        now = timezone.now()
        totp = pyotp.TOTP(user.otp_secret, interval=TOTP_INTERVAL, digits=6)
        otp = totp.at(now)  # equivalente a totp.now() pero con tz

        # Enviar correo
        domain = Site.objects.get_current().domain
        send_mail(
            subject="Your OTP Code",
            message=f"Your OTP code is {otp}",
            from_email=f"no-reply@{domain}",
            recipient_list=[email],
            fail_silently=False,
        )

        return self.response("OTP sent successfully.")


class VerifyOTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        otp_code = str((request.data.get("otp") or "")).strip()

        if not email or not otp_code:
            return self.error("Both email and OTP code are required.")

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return self.error("User does not exist or is not active.")

        if not getattr(user, "otp_secret", None):
            return self.error("No OTP secret registered for this user.")

        now = timezone.now()
        totp = pyotp.TOTP(user.otp_secret, interval=TOTP_INTERVAL, digits=6)

        # (Opcional) Anti-reuso: solo si el modelo tiene el campo otp_last_counter
        anti_reuse_enabled = hasattr(user, "otp_last_counter")
        if anti_reuse_enabled:
            current_counter = totp.timecode(now)
            last_counter = getattr(user, "otp_last_counter", None)
            if last_counter is not None and current_counter <= last_counter:
                return self.error("OTP already used.")

        # Verificación con tolerancia de ventana y tiempo aware
        if totp.verify(otp_code, valid_window=TOTP_VALID_WINDOW, for_time=now):
            if anti_reuse_enabled:
                user.otp_last_counter = totp.timecode(now)
                user.save(update_fields=["otp_last_counter"])

            refresh = RefreshToken.for_user(user)
            return self.response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            })

        return self.error("Invalid or expired OTP.")