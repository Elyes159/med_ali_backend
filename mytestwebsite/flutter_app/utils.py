import datetime
from email.message import EmailMessage
from random import randint
import uuid
from django.http import JsonResponse
from rest_framework.response import Response
from django.template.loader import get_template
from django.utils.html import strip_tags
from django.template import Context
from flutter_app.models import Otp, PasswordResetToken, Token
from mytestwebsite.settings import TEMPLATES_BASE_URL
from rest_framework.permissions import BasePermission
from django.utils import timezone


def send_otp(phone):
    otp = randint(100000, 999999)
    validity = datetime.datetime.now() + datetime.timedelta(minutes=10)
    Otp.objects.update_or_create(phone=phone, defaults={"otp": otp, "verified": False, "validity": validity})
    # Ajoutez ici la logique pour envoyer l'OTP par SMS

    print(otp)
    
    response_data = {
        'message': 'OTP sent successfully',
        'phone': phone,
        # Ajoutez d'autres données si nécessaire
    }
    return JsonResponse(response_data)
def new_token() : 
    token = uuid.uuid1().hex
    return token
def token_response(user):
    token = new_token()
    Token.objects.create(token=token, user=user) 
    response_data = {
        'message': 'login successful',
        'token': token,
        'email' : user.email,
        'fullname' : user.fullname,
        'phone' : user.phone

    }
    print(token)

    return JsonResponse(response_data)
from django.core.mail import send_mail

def send_password_reset_email(user):
    token = new_token()
    exp_time = timezone.now() + timezone.timedelta(minutes=10)

    PasswordResetToken.objects.update_or_create(user=user, defaults={'user': user, 'token': token, 'validity': exp_time})

    email_data = {
        'token': token,
        'email': user.email,
        'base_url': TEMPLATES_BASE_URL
    }

    email_template = get_template('emails/reset-password.html')
    message = email_template.render(email_data)

    subject = 'Reset Password'
    recipients = [user.email]

    try:
        send_mail(subject, message, from_email=None, recipient_list=recipients, html_message=message)
        return JsonResponse({'message': 'reset_password_email_sent'})
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")
        return JsonResponse({'error': 'Failed to send reset password email'}, status=500)
    
class IsAuthenticatedUser(BasePermission) :
    message = 'unauthenticated_user'

    def has_permission(self,request,view) : 
        return bool(request.user)
