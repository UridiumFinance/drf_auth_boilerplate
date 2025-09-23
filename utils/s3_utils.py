import datetime
import logging
from functools import lru_cache
from typing import Optional

from botocore.signers import CloudFrontSigner
from django.conf import settings
from django.utils import timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger(__name__)

DEFAULT_CF_URL_TTL = getattr(settings, "CLOUDFRONT_URL_TTL", 60)
MIN_CF_URL_TTL = getattr(settings, "CLOUDFRONT_MIN_URL_TTL", 10)
MAX_CF_URL_TTL = getattr(settings, "CLOUDFRONT_MAX_URL_TTL", 86400)

def normalize_ttl(ttl: Optional[int], default_ttl: int = DEFAULT_CF_URL_TTL) -> int:
    """
    Recibe un TTL (segundos) y lo normaliza:
    - usa default si viene None o inválido
    - aplica límites MIN/MAX para seguridad
    """
    try:
        ttl_int = int(ttl) if ttl is not None else int(default_ttl)
    except (TypeError, ValueError):
        ttl_int = int(default_ttl)
    return max(MIN_CF_URL_TTL, min(ttl_int, MAX_CF_URL_TTL))


def generate_presigned_url(s3_client, client_method, method_parameters, expires_in: int):
    """
    Helper para prefirmado S3 directo (no CloudFront).
    Mantén esta utilidad si usas presign de S3 además de CloudFront.
    """
    try:
        url = s3_client.generate_presigned_url(
            clientMethod=client_method,
            Params=method_parameters,
            ExpiresIn=expires_in,
        )
        logger.info("Got presigned URL: %s", url)
        return url
    except Exception:
        logger.exception("Couldn't get a presigned URL for client method '%s'.", client_method)
        raise


@lru_cache(maxsize=1)
def _load_private_key():
    """
    Carga y cachea la llave privada usada por CloudFrontSigner.
    Asume `settings.AWS_CLOUDFRONT_KEY` en formato PEM string/bytes.
    """
    key_data = settings.AWS_CLOUDFRONT_KEY
    if isinstance(key_data, str):
        key_data = key_data.encode("utf-8")
    return serialization.load_pem_private_key(
        key_data,
        password=None,  # ajusta si tu llave tiene passphrase
        backend=default_backend(),
    )


def rsa_signer(message: bytes) -> bytes:
    """
    Firma requerida por CloudFrontSigner. No exponer directamente.
    """
    private_key = _load_private_key()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1(),  # CloudFront RSA-SHA1 (legacy requirement)
    )
    return signature


def get_cloudfront_signed_url(key: str, expires_in: Optional[int] = None) -> Optional[str]:
    if not key:
        return None

    # 👇 usa normalize_ttl para respetar límites y default
    ttl = normalize_ttl(expires_in, default_ttl=DEFAULT_CF_URL_TTL)

    base_url = f"https://{settings.AWS_CLOUDFRONT_DOMAIN}/{key}"
    key_id = settings.AWS_CLOUDFRONT_KEY_ID
    signer = CloudFrontSigner(key_id, rsa_signer)
    expire_date = timezone.now() + datetime.timedelta(seconds=ttl)
    return signer.generate_presigned_url(base_url, date_less_than=expire_date)
