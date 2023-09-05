from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import Verify




User=get_user_model()
class UserSerial(serializers.ModelSerializer):
    class Meta:
        model=User
        fields='__all__'


class VerifySerial(serializers.ModelSerializer):
    class Meta:
        model=Verify
        fields='__all__'