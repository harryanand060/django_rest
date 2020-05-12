from django.urls import path
from . import views

urlpatterns = [
    path('register', views.Register.as_view(), name='register'),
    path('verify', views.Verify.as_view(), name='verify'),
    path('resent', views.Resent.as_view(), name='reset'),
    path('login', views.Login.as_view(), name='login'),
    path('profile', views.Profiles.as_view(), name='profile'),
]
