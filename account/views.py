# Create your views here.

import uuid
from rest_framework.response import Response
from rest_framework import generics
from rest_framework import permissions
from rest_framework import status
from rest_framework_jwt.serializers import RefreshJSONWebTokenSerializer
from rest_framework_jwt.views import JSONWebTokenAPIView
from django.utils.text import gettext_lazy as _

from django.contrib.auth import authenticate
from django.contrib.auth import logout
from django.contrib.auth import login

from account.serializers import UserChangePasswordSerializer
from common.helper import CommonHelper
from account import serializers
from account import models


class Register(generics.CreateAPIView):
    """
      Account Register with mobile or email and password
    """

    model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserCreateSerializer

    def post(self, request, *args, **kwargs):
        """
        Method used for user registration with mobile or email, password, first name , last name,
        :param request: using this parameter user get email or mobile no and password, name
        :param args: None
        :param kwargs: None
        :return:True: Success
                False: Failed
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            raise serializers.ValidationError(serializer.errors, code=status.HTTP_200_OK)
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
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        return Response(CommonHelper.render(True, None, message, status.HTTP_201_CREATED))


class Verify(generics.CreateAPIView):
    """
    Verify Registred email or mobile with otp
    mobile otp only verify mobile so user can only login with mobile
    email otp only verify email so user can only login with email
    """
    # model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserVerifySerializer

    def post(self, request, *args, **kwargs):
        """
        Verify Registered email or mobile with otp
        mobile otp only verify mobile so user can only login with mobile
        email otp only verify email so user can only login with email
        :param request: using this parameter user get email or mobile no.
        :param args: None
        :param kwargs: None
        :return:True: Success
                False: Failed
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            raise serializers.ValidationError(serializer.errors, code=status.HTTP_200_OK)
        try:
            kwargs = CommonHelper.email_or_mobile(serializer.initial_data["device"])
            key = next(iter(kwargs))
            user = CommonHelper.user_exists(**kwargs)
            if not user:
                return Response(CommonHelper.render(False, None, _("User not exists"), status.HTTP_200_OK))
            verify = user.verification.verify_otp(key, serializer.initial_data["otp"])
            if not verify:
                return Response(CommonHelper.render(False, None, _("invalid otp"), status.HTTP_200_OK))
            # login and create session
            login(request, user)
        except Exception as ex:
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        data = {"token": user.token}
        return Response(CommonHelper.render(True, data, _("Success"), status.HTTP_201_CREATED))


class Resent(generics.CreateAPIView):
    """
    Resent OTP
    """
    # model = models.User
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.ResentSerializer

    def post(self, request, *args, **kwargs):
        """
        Resent OTP on mail and email. OTP valid for 15 min only.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            raise serializers.ValidationError(serializer.errors, code=status.HTTP_200_OK)
        try:
            kwargs = CommonHelper.email_or_mobile(serializer.initial_data["device"])
            user = CommonHelper.user_exists(**kwargs)
            if not user:
                return Response(CommonHelper.render(False, None, "User not exists", status.HTTP_200_OK))
            user.verification.generate_otp()
            message = f"Verification OTP sent to {user.mobile} and {user.email}"
        except Exception as ex:
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        return Response(CommonHelper.render(True, None, message, status.HTTP_201_CREATED))


class Login(generics.CreateAPIView):
    """
     Account Login with mobile or email with password
    """
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.UserLoginSerializer

    def post(self, request, *args, **kwargs):
        """
        Method used for authentication of the system. using registered mobile or email user can login to the system
        :param request: using this parameter user get email or mobile no and password
        :param args: None
        :param kwargs: None
        :return: After successful authentication user get status as True and data as auth token
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            raise serializers.ValidationError(serializer.errors, code=status.HTTP_200_OK)
        try:
            kwargs = CommonHelper.email_or_mobile(serializer.initial_data["device"])
            credentials = {'password': serializer.initial_data['password']}
            credentials.update(**kwargs)
            user = authenticate(**credentials)
            if user is None:
                message = _("Please enter valid {device} and password")
                message = message.format(device=next(iter(kwargs)))
                return Response(CommonHelper.render(False, None, message, status.HTTP_200_OK))

            is_active = getattr(user, 'is_active', None)
            if not is_active:
                data = {"active": False}
                return Response(CommonHelper.render(False, data, "account is not activated", status.HTTP_200_OK))

            if kwargs.get(user.EMAIL_FIELD, False) and not user.verification.email_verified:
                data = {"email verification": False}
                return Response(CommonHelper.render(False, data, "email is not verified! you can not login with email",
                                                    status.HTTP_200_OK))

            elif kwargs.get(user.USERNAME_FIELD, False) and not user.verification.mobile_verified:
                data = {"mobile verification": False}
                return Response(
                    CommonHelper.render(False, data, "mobile is not verified! you can not login with mobile",
                                        status.HTTP_200_OK))

        except Exception as ex:
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        data = {"token": user.token}
        return Response(CommonHelper.render(True, data, "success", status.HTTP_201_CREATED))


class UserExists(generics.RetrieveAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.ResentSerializer

    def get(self, request, *args, **kwargs):
        """
        Method to check user already exists or not
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            serializer = self.serializer_class(data=kwargs)
            # if not serializer.is_valid():
            #     raise serializers.ValidationError(serializer.errors, code=status.HTTP_200_OK)
            kwargs = CommonHelper.email_or_mobile(serializer.initial_data["device"])
            user = CommonHelper.user_exists(**kwargs)
            if not user:
                return Response(CommonHelper.render(False, None, _("User not exists"), status.HTTP_200_OK))
        except Exception as ex:
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        return Response(CommonHelper.render(True, True, _("User found"), status.HTTP_200_OK))


class ChangePassword(generics.GenericAPIView):
    serializer_class = UserChangePasswordSerializer

    def put(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(CommonHelper.render(True, True, _("Password Updated Successfully"), status.HTTP_200_OK))


class RefreshToken(JSONWebTokenAPIView):
    serializer_class = RefreshJSONWebTokenSerializer

    def post(self, request, *args, **kwargs):
        """
        Method to refresh the token. Token refresh only valid till original token not expired
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        response = super(RefreshToken, self).post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            return Response(CommonHelper.render(True, response.data, "success", response.status_code))
        return Response(CommonHelper.render(False, None, response.data["non_field_errors"], response.status_code))


class Profile(generics.RetrieveAPIView):
    model = models.User
    serializer_class = serializers.UserSerializer

    def get(self, request, *args, **kwargs):
        """
        Method to get authenticate user profile information
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(request.user)
        return Response(CommonHelper.render(True, serializer.data, "success", status.HTTP_201_CREATED))


class Logout(generics.RetrieveAPIView):

    def get(self, request, *args, **kwargs):
        """
        Method to logout and invalid the token
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            user = request.user
            user.jwt_secret = uuid.uuid4()
            user.save()
            logout(request)
        except Exception as ex:
            return Response(CommonHelper.render(False, None, ex.args, status.HTTP_200_OK))
        return Response(CommonHelper.render(True, None, "Logout Successfully", status.HTTP_201_CREATED))
