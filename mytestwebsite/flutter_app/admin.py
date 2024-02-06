from django.contrib import admin
from django.contrib.admin import register

from flutter_app.models import Otp, PasswordResetToken, Token, User
# Register your models here.



@register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email','phone','fullname','created_at']

@register(Otp)
class OtpAdmin(admin.ModelAdmin) : 
    list_display = ['phone', 'otp','validity','verified']

@register(Token)
class TokenAdmin(admin.ModelAdmin) : 
    list_display = ['token','user','created_at']


@register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin) : 
    list_display=['token','user','created_at']