import random
from datetime import datetime, timedelta
from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.views.generic import View, TemplateView
from django.contrib.auth.models import User, Group
from django.contrib.sessions.models import Session
from django.contrib.auth import authenticate, login, logout, get_backends
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.admin.models import LogEntry
from django.contrib.auth.decorators import login_required
from RBACManager import settings

def send_otp(request, email, subject, message):
    otp = random.randint(100000, 999999)
    request.session['otp'] = otp
    request.session['otp_timestamp'] = datetime.now().isoformat()
    request.session['user_email'] = email

    send_mail(
        subject,
        message + f' {otp}',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

def is_otp_expired(request, expiry_minutes=10):
    otp_timestamp = request.session.get('otp_timestamp')
    if otp_timestamp:
        otp_time = datetime.fromisoformat(otp_timestamp)
        if datetime.now() - otp_time > timedelta(minutes=expiry_minutes):
            return True
    return False

def email_validator(request, email):
    valid_email = set([
        'gmail.com',
        'yahoo.com',
        'hotmail.com',
        'outlook.com',
        'protonmail.com',
        'icloud.com',
        'yandex.com',
    ])
    domain = email.split('@')[1]
    
    return domain in valid_email


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        is_admin = self.request.user.groups.filter(name='admin').exists()
        is_moderator = self.request.user.groups.filter(name='moderator').exists()
        is_user = self.request.user.groups.filter(name='user').exists()

        context['is_admin'] = is_admin
        context['is_moderator'] = is_moderator
        context['is_user'] = is_user

        return context
    
    
class UserProfileView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        user = request.user
        is_admin = request.user.groups.filter(name='admin').exists()
        is_moderator = request.user.groups.filter(name='moderator').exists()

        if is_admin or is_moderator:
            users = User.objects.all()
        else:
            users = [user]

        return render(request, 'profile.html', {
            'user': user,
            'users': users,
            'is_admin': is_admin,
            'is_moderator': is_moderator
        })

    def post(self, request, *args, **kwargs):
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')

        try:
            user = request.user
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()

            messages.success(request, "Profile updated successfully")
        except Exception as e:
            messages.error(request, f"Error updating profile: {e}")
        return redirect('profile')
    
    
class AutoLoginAdminView(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.user.groups.filter(name='admin').exists():
            login(request, request.user)
            return redirect('/admin')
        else:
            messages.error(request, "You do not have permission to access this page.")
            return HttpResponseForbidden("Access Denied")

class LoginView(View):
    template_name = 'login.html'

    def get(self, request):
        users = User.objects.all()
        return render(request, self.template_name, {'users': users})

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not User.objects.filter(username=username).exists():
            messages.error(request, 'User not found')
            return redirect('register')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            send_otp(request, User.objects.get(username=username).email, 'Login OTP', 'Your OTP for login is')
            messages.info(request, 'An OTP has been sent to your email. Please verify.')
            request.session['role'] = user.groups.first().name
            request.session['temp_user_id'] = user.id
            return redirect('verify_otp')
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
        
        if not email_validator(request, email):
            messages.error(request, 'Invalid email domain. Please use a valid email address.')
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
        temp_user_id = request.session.get('temp_user_id')
        
        if not temp_user_id:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('login')
        
        if is_otp_expired(request):
            messages.error(request, 'OTP expired. Please request a new one.')
            return redirect('verify_otp')

        if str(entered_otp) == str(session_otp):
            user_data = request.session.get('user_data')
            if temp_user_id:
                user = User.objects.filter(id=temp_user_id).first()
                
                backends = get_backends()
                
                if backends:
                    user.backend = f"{backends[0].__module__}.{backends[0].__class__.__name__}"

                login(request, user)
                
                del request.session['otp']
                del request.session['temp_user_id']
                
                return redirect('home')
                
            elif user_data:
                user = User.objects.create_user(
                    first_name=user_data['first_name'],
                    last_name=user_data['last_name'],
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password']
                )
                
                default_group = Group.objects.get(name='Viewer')
                user.groups.add(default_group)
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
            User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return redirect('password_reset_request')

        send_otp(request, email, 'Password Reset OTP', 'Your OTP for password reset is')

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

@login_required
def moderator_dashboard(request):
    if not request.user.groups.filter(name='moderator').exists():
        return HttpResponseForbidden('You do not have permission to access this page.')

    logs = LogEntry.objects.all().order_by('-action_time')
    sessions = Session.objects.all()
    
    return render(request, 'moderator_dashboard.html', {'logs': logs, 'sessions': sessions})