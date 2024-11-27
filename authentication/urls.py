from django.urls import path
from .views import AutoLoginAdminView, LoginView, RegisterView, HomeView, LogoutView, VerifyOTPView, PasswordResetRequestView, PasswordResetVerifyView, UserProfileView
from authentication import views

urlpatterns = [
    path('home/', HomeView.as_view(), name='home'),
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/verify/', PasswordResetVerifyView.as_view(), name='password_reset_verify'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('login-admin/', AutoLoginAdminView.as_view(), name='auto_login_admin'),
    path('moderator/dashboard/', views.moderator_dashboard, name='moderator_dashboard'),
]
