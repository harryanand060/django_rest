from rest_framework import serializers
from rest_framework import status
from django.utils.text import gettext_lazy as _

from common.core.validators import validate_user
from account.models import User, Verification


class UserCreateSerializer(serializers.ModelSerializer):
    # """
    #   UserCreateSerializer is a model serializer which includes the attributes that are required for registering a user.
    #   Examples
    # """
    # password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    password = serializers.CharField(
        max_length=128, min_length=8, required=True, write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('mobile', 'email', 'first_name', 'last_name', 'password')


class UserVerifySerializer(serializers.ModelSerializer):
    otp = serializers.IntegerField(required=True)
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validate_user], required=True)

    class Meta:
        model = User
        fields = ('device', 'otp',)


class ResentSerializer(serializers.ModelSerializer):
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validate_user], required=True)

    class Meta:
        model = User
        fields = ('device',)


class UserLoginSerializer(serializers.ModelSerializer):
    device = serializers.CharField(help_text=_("Email Or Mobile"), validators=[validate_user], required=True)
    password = serializers.CharField(help_text=_("Password"), max_length=128, min_length=8, required=True,
                                     write_only=True,
                                     style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('device', 'password',)


class VerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Verification
        fields = ('mobile_verified','email_verified')


class UserSerializer(serializers.ModelSerializer):
    verification = VerificationSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id','mobile', 'email', 'is_active', 'is_superuser', 'verification')


class ValidationError(serializers.ValidationError):
    status_code = status.HTTP_200_OK
