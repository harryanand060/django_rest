from django.urls import path
from account import views

urlpatterns = [
    path(r'register', views.Register.as_view(), name='register'),
    path(r'verify', views.Verify.as_view(), name='verify'),
    path(r'resent', views.Resent.as_view(), name='reset'),
    path(r'login', views.Login.as_view(), name='login'),
    path(r'exist/<str:device>', views.UserExists.as_view(), name='exist'),
    path(r'profile', views.Profile.as_view(), name='profile'),
    path(r'logout', views.Logout.as_view(), name='logout'),
    path(r'token-refresh/', views.RefreshToken.as_view(), name='refresh-token')
]
