from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin

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
            return redirect('login')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home page
        else:
            messages.error(request, 'Invalid credentials')
            return redirect('login')


class RegisterView(View):
    template_name = 'register.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('login')

        User.objects.create_user(username=username, password=password) 
        messages.success(request, 'Registration successful! You can now log in.')
        return redirect('login')
    
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('login')
