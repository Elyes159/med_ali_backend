"""mytestwebsite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from flutter_app.views import  create_account, password_reset_form, request_otp, verify_otp,password_reset_email
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('request_otp/',request_otp, name = 'request_otp'),
    path('verify_otp/', verify_otp),
    path('create_account/',create_account, name = 'create_account'),
    path('password_reset_email/',password_reset_email,name='password_reset_email'),
    path('password_reset_form/<email>/<token>',password_reset_form,name='password_reset_form'),
]
