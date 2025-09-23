import time
import datetime
import pyotp

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils import timezone

# ====== Parámetros OTP ======
TOTP_INTERVAL = getattr(settings, "TOTP_INTERVAL", 30)          # 30s es estándar
TOTP_VALID_WINDOW = getattr(settings, "TOTP_VALID_WINDOW", 1)    # acepta ±1 ventana (hasta ~±30s)
TOTP_DIGITS = getattr(settings, "TOTP_DIGITS", 6)

# ====== Rate limiting ======
# Ventana mínima entre envíos por usuario
OTP_SEND_COOLDOWN_SECONDS = getattr(settings, "OTP_SEND_COOLDOWN_SECONDS", 30)
# Límite duro por hora (anti abuso)
OTP_SEND_MAX_PER_HOUR = getattr(settings, "OTP_SEND_MAX_PER_HOUR", 10)

def _get_from_email(request):
    # 1) Usa DEFAULT_FROM_EMAIL si existe
    default_from = getattr(settings, "DEFAULT_FROM_EMAIL", None)
    if default_from:
        return default_from
    # 2) Fallback con dominio del Site o del host de la request
    try:
        domain = get_current_site(request).domain
    except Exception:
        domain = (request.get_host() or "example.com").split(":")[0]
    return f"no-reply@{domain}"

def _otp_expires_in_seconds():
    # segundos restantes de la ventana actual (solo informativo)
    now_unix = int(time.time())
    return TOTP_INTERVAL - (now_unix % TOTP_INTERVAL)

def _throttle_send_key(user_id):
    return f"otp:send:cooldown:{user_id}"

def _hour_counter_key(user_id):
    # llave única por hora (UTC) para contar envíos
    hour_bucket = timezone.now().replace(minute=0, second=0, microsecond=0)
    return f"otp:send:hour:{user_id}:{int(hour_bucket.timestamp())}"

def _check_rate_limit(user):
    # cooldown corto
    if cache.get(_throttle_send_key(user.id)):
        return False, "OTP recently sent. Please wait a few seconds."
    # contador por hora
    hk = _hour_counter_key(user.id)
    count = cache.get(hk, 0)
    if count >= OTP_SEND_MAX_PER_HOUR:
        return False, "OTP rate limit reached. Try again later."
    return True, None

def _register_send(user):
    # setea cooldown y cuenta
    cache.set(_throttle_send_key(user.id), True, timeout=OTP_SEND_COOLDOWN_SECONDS)
    hk = _hour_counter_key(user.id)
    count = cache.get(hk, 0)
    # Expira al final de la hora actual (≈ 3600s desde el inicio)
    ttl = 3600 - (timezone.now().minute * 60 + timezone.now().second)
    cache.set(hk, count + 1, timeout=max(ttl, 60))

def _totp_for_user(user):
    return pyotp.TOTP(user.otp_secret, interval=TOTP_INTERVAL, digits=TOTP_DIGITS)

def _verify_and_get_counter(totp, code, now):
    """
    Verifica el code y devuelve el 'counter' exacto usado.
    Evita falsos negativos con valid_window permitiendo +/- ventanas,
    pero además sabemos exactamente en qué ventana fue válido para bloquear reuso.
    """
    base_counter = totp.timecode(now)
    # Preferimos la ventana más reciente primero: +1, 0, -1, -2, ...
    windows = list(range(TOTP_VALID_WINDOW, -TOTP_VALID_WINDOW-1, -1))
    for w in windows:
        t = now + datetime.timedelta(seconds=TOTP_INTERVAL * w)
        # valid_window=0 porque ya "movemos" el tiempo manualmente
        if totp.verify(code, for_time=t, valid_window=0):
            return base_counter + w
    return None
