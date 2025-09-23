import mimetypes

import boto3
from django import forms
from django.conf import settings

from .models import Media


class MediaAdminForm(forms.ModelForm):
    file = forms.FileField(required=False)
    s3_path = forms.CharField(
        required=False,
        help_text="Ruta S3 opcional. Ej: profiles/avatars",
        label="Ruta personalizada"
    )

    class Meta:
        model = Media
        fields = ['file', 's3_path', 'media_type', 'order']

    def clean(self):
        cleaned_data = super().clean()
        uploaded_file = cleaned_data.get('file')
        custom_path = cleaned_data.get('s3_path', '').strip().strip('/')

        if uploaded_file:
            s3 = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_S3_REGION_NAME,
            )

            bucket = settings.AWS_STORAGE_BUCKET_NAME
            file_name = uploaded_file.name
            content_type = mimetypes.guess_type(file_name)[0] or 'application/octet-stream'

            if custom_path:
                key = f"media/{custom_path}/{file_name}"
            else:
                key = f"media/{file_name}"

            # Subida a S3 con ContentType y ContentDisposition correctos
            s3.upload_fileobj(
                uploaded_file,
                bucket,
                key,
                ExtraArgs={
                    'ContentType': content_type,
                    'ContentDisposition': 'inline'  # 👈 Esto permite visualizar en navegador
                }
            )

            # Actualizar instancia
            self.instance.name = file_name
            self.instance.size = uploaded_file.size
            self.instance.key = key
            self.instance.type = content_type

        return cleaned_data