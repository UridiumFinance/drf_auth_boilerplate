from rest_framework import serializers

from .models import UserProfile
from apps.assets.serializers import MediaSerializer


class UserProfileSerializer(serializers.ModelSerializer):
    profile_picture     = serializers.SerializerMethodField()
    banner_picture      = serializers.SerializerMethodField()
    class Meta:
        model = UserProfile
        fields = [
            'profile_picture',
            'banner_picture',
            'biography',
            'birthday',
            'website',
            'instagram',
            'facebook',
            'threads',
            'linkedin',
            'youtube',
            'tiktok',
            'github',
            'gitlab',
        ]
    
    def get_profile_picture(self, obj):
        if obj and obj.profile_picture:
            return MediaSerializer(obj.profile_picture).data.get("url")
        return None
    
    def get_banner_picture(self, obj):
        if obj and obj.banner_picture:
            return MediaSerializer(obj.banner_picture).data.get("url")
        return None