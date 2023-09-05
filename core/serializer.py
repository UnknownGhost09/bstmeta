from django.contrib.auth import get_user_model
User=get_user_model()
from .models import UserReferral


from rest_framework import serializers

class Userserial(serializers.ModelSerializer):
    class Meta:
        model=User
        fields='__all__'

class referserial(serializers.ModelSerializer):
    class Meta:
        model=UserReferral
        fields='__all__'
