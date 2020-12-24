from django.contrib.auth import password_validation
from django.contrib.auth.password_validation import validate_password
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
                                     write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('device', 'password',)


class UserChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(help_text=_("Current Password"), max_length=128, min_length=8, required=True,
                                         write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(help_text=_("New Password"), max_length=128, min_length=8, required=True,
                                         write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(help_text=_("Confirm Password"), max_length=128, min_length=8,
                                             required=True,
                                             write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('old_password', 'new_password', 'confirm_password')

    def validate_old_password(self, value):
        user = self.context.get("request").user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _('Your old password was entered incorrectly. Please enter it again.')
            )
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': _("The two password fields didn't match.")})
        password_validation.validate_password(attrs['new_password'], self.context['request'].user)
        return attrs

    def save(self, **kwargs):
        password = self.validated_data['new_password']
        user = self.context.get("request").user
        user.set_password(password)
        user.save()
        return user

    # def update(self, instance, validated_data):
    #     password = self.validated_data['new_password']
    #     instance.set_password(password)
    #     instance.save()
    #     return instance


class VerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Verification
        fields = ('mobile_verified', 'email_verified')


class UserSerializer(serializers.ModelSerializer):
    verification = VerificationSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'mobile', 'email', 'is_active', 'is_superuser', 'verification')


class ValidationError(serializers.ValidationError):
    status_code = status.HTTP_200_OK
