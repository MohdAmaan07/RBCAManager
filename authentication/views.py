import random
from django.shortcuts import render, redirect
from django.views.generic import View, TemplateView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'home.html'

class LoginView(View):
    template_name = 'login.html'

    def get(self, request):
        users = User.objects.all()  # Optional: Remove if not used in the template
        return render(request, self.template_name, {'users': users})

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not User.objects.filter(username=username).exists():
            messages.error(request, 'User not found')
            return redirect('register')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid credentials')
            return redirect('login')


class RegisterView(View):
    template_name = 'register.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            validate_password(password)
            
        except ValidationError as e:
            messages.error(request, e)
            return redirect('register')
        
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('login')

        otp = random.randint(100000, 999999)
        request.session['otp'] = otp 
        request.session['user_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'username': username,
            'email': email,
            'password': password
        }

        send_mail(
            'Email Verification OTP',
            f'Your OTP for email verification is {otp}',
            'your_email@example.com',
            [email],
            fail_silently=False,
        )

        messages.info(request, 'An OTP has been sent to your email. Please verify.')
        return redirect('verify_otp')


class VerifyOTPView(View):
    template_name = 'verify_otp.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        entered_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')

        if str(entered_otp) == str(session_otp):
            user_data = request.session.get('user_data')
            if user_data:
                User.objects.create_user(
                    first_name=user_data['first_name'],
                    last_name=user_data['last_name'],
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password']
                )
                messages.success(request, 'Registration successful! You can now log in.')
                del request.session['otp']
                del request.session['user_data']
                return redirect('login')

        messages.error(request, 'Invalid OTP. Please try again.')
        return redirect('verify_otp')

class PasswordResetRequestView(View):
    template_name = 'password_reset_request.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return redirect('password_reset_request')

        otp = random.randint(100000, 999999)
        request.session['otp'] = otp
        request.session['user_email'] = email

        send_mail(
            'Password Reset OTP',
            f'Your OTP for password reset is {otp}',
            'your_email@example.com',
            [email],
            fail_silently=False,
        )

        messages.info(request, 'An OTP has been sent to your email. Please check your inbox.')
        return redirect('password_reset_verify')


class PasswordResetVerifyView(View):
    template_name = 'password_reset_verify.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        entered_otp = request.POST.get('otp')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        session_otp = request.session.get('otp')
        email = request.session.get('user_email')

        if not email or not session_otp:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('password_reset_request')

        if str(entered_otp) != str(session_otp):
            messages.error(request, 'Invalid OTP.')
            return redirect('password_reset_verify')

        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('password_reset_verify')

        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()

            del request.session['otp']
            del request.session['user_email']

            messages.success(request, 'Password reset successful! You can now log in.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'An error occurred. Please try again.')
            return redirect('password_reset_request')


class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('login')
