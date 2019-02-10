from rest_framework import serializers, status
from .utils import validators
from django.utils.text import gettext_lazy as _
from .models import User


class UserCreateSerializer(serializers.ModelSerializer):
    # """
    #   UserCreateSerializer is a model serializer which includes the attributes that are required for registering a user.
    #   Examples
    # --------
    # >>> print(UserCreateSerializer(data={'username':'test@testing.com', 'name':'test', 'email': 'test@testing.com', 'mobile' : '123456', 'password': '123780'}))
    # """
    # password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    password = serializers.CharField(
        max_length=128, min_length=8, required=True, write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('mobile', 'email', 'first_name', 'last_name', 'password')


class UserVerifySerializer(serializers.ModelSerializer):
    otp = serializers.IntegerField(required=True)
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validators.validate_user], required=True)

    class Meta:
        model = User
        fields = ('device', 'otp',)


class ResentSerializer(serializers.ModelSerializer):
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validators.validate_user], required=True)

    class Meta:
        model = User
        fields = ('device',)


class UserLoginSerializer(serializers.ModelSerializer):
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validators.validate_user], required=True)
    password = serializers.CharField(max_length=128, min_length=8, required=True, write_only=True,
                                     style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('device', 'password',)
