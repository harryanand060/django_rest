# Create your views here.

from rest_framework.response import Response
from rest_framework import generics, permissions, status
from django.utils.text import gettext_lazy as _
from . import serializers, models
from common import helper
from .utils import account_helper
from django.contrib.auth import authenticate, login


class Register(generics.CreateAPIView):
    """
      Account Register
    """

    model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserCreateSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = self.model.objects.create_user(
                mobile=serializer.initial_data['mobile'],
                email=serializer.initial_data['email'],
                password=serializer.initial_data['password'],
                first_name=serializer.initial_data['first_name'],
                last_name=serializer.initial_data['last_name'],
            )
            otp = models.Verification.objects.create(
                user=user,
                unverified_mobile=user.mobile,
                unverified_email=user.email
            )
            otp.generate_otp()
            message = _("Verification Token sent to {phone} and {email} ")
            message = message.format(phone=user.mobile, email=user.email)
        except Exception as ex:
            return Response(helper.render(False, None, ex.args, status.HTTP_500_INTERNAL_SERVER_ERROR))
        return Response(helper.render(True, None, message, status.HTTP_201_CREATED))


class Verify(generics.CreateAPIView):
    # model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            kwargs = account_helper.email_or_mobile(serializer.initial_data["device"])
            key = next(iter(kwargs))
            user = account_helper.user_exists(**kwargs)
            if not user:
                return Response(helper.render(False, None, _("User not exists"), status.HTTP_400_BAD_REQUEST))
            verify = user.verification.verify_otp(key, serializer.initial_data["otp"])
            if not verify:
                return Response(helper.render(False, None, _("invalid otp"), status.HTTP_401_UNAUTHORIZED))

            # login and create session
            login(request, user)

        except Exception as ex:
            return Response(helper.render(False, None, ex.args, status.HTTP_500_INTERNAL_SERVER_ERROR))
        return Response(helper.render(True, {"token": user.token}, _("successful"), status.HTTP_201_CREATED))


class Resent(generics.CreateAPIView):
    # model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.ResentSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            kwargs = account_helper.email_or_mobile(serializer.initial_data["device"])
            user = account_helper.user_exists(**kwargs)
            user.verification.generate_otp()
            message = _("Verification Token sent to {phone} and {email}")
            message = message.format(phone=user.mobile, email=user.email)
        except Exception as ex:
            return Response(helper.render(False, None, ex.args, status.HTTP_500_INTERNAL_SERVER_ERROR))
        return Response(helper.render(True, None, message, status.HTTP_201_CREATED))


class Login(generics.CreateAPIView):
    """
     Account Login
    """
    from rest_framework_jwt.serializers import JSONWebTokenSerializer, jwt_payload_handler, jwt_encode_handler
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            kwargs = account_helper.email_or_mobile(serializer.initial_data["device"])
            credentials = {'password': serializer.initial_data['password']}
            credentials.update(**kwargs)
            user = authenticate(**credentials)
            if user is None:
                message = _("Please enter valid {device} and password")
                message = message.format(device=next(iter(kwargs)))
                return Response(helper.render(False, None, message, status.HTTP_401_UNAUTHORIZED))

            is_active = getattr(user, 'is_active', None)
            if not is_active:
                data = {"active": False}
                return Response(helper.render(False, data, "account is not activated", status.HTTP_401_UNAUTHORIZED))

        except Exception as ex:
            return Response(helper.render(False, None, ex.args, status.HTTP_500_INTERNAL_SERVER_ERROR))
        return Response(helper.render(True, {"token": user.token}, "success", status.HTTP_201_CREATED))


class UserProfile(generics.ListAPIView):
    pass
