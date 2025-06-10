# 🚀 DRF Auth Boilerplate

Una base sólida para proyectos con Django REST Framework, integración con Docker, AWS S3 + CloudFront, ASGI (Uvicorn/Channels) y autenticación moderna (JWT + 2FA). Ideal para acelerar el desarrollo de APIs seguras y escalables.

---

## 🧱 Stack Principal

| Parte | Tecnología |
|-------|------------|
| **Backend** | Django 5.x + Django REST Framework |
| **API** | Uvicorn + ASGI |
| **Autenticación** | JWT (SimpleJWT) + 2FA (OTP) |
| **Multimedia** | AWS S3 + CloudFront |
| **Contenedores** | Docker + Docker Compose |
| **CORS/CSRF** | django-cors-headers |

---

## ✅ Características

- Usuario personalizado (`UserAccount`) con 2FA vía QR usando pyOTP + qrcode.
- Iran conexión basada en `Media` para gestión uniforme de assets (imágenes, videos, documentos).
- Subida a S3 con URLs públicas/privadas firmadas por CloudFront.
- Admin de Django estilizado con ASGIMiddleware y almacenamiento en S3.
- CORS configurado para desarrollo y producción.
- Integración de ASGI Channels + Redis + Django Channels para WebSockets.

---

## 🛠️ Instalación

1. **Clona el repositorio**

   ```bash
   git clone https://github.com/UridiumFinance/drf_auth_boilerplate.git
   cd drf_auth_boilerplate
   cp .env.example .env

2. **Configura el `.env`**
    
    Rellena variables como `SECRET_KEY`, AWS_ACCESS_KEY_ID, S3_BUCKET, CLOUDFRONT_DOMAIN, REDIS_URL, etc.

3. **Levanta con Docker**

    ```bash
    docker compose up --build

4. **Aplica migraciones y carga archivos estáticos**

    ```bash
    docker compose exec web python manage.py migrate
    docker compose exec web python manage.py collectstatic --noinput
