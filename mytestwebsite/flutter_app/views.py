import datetime
import json
import logging
from random import randint
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404,redirect
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from flutter_app.models import Otp, PasswordResetToken, Token, User
from flutter_app.utils import IsAuthenticatedUser, send_otp, send_password_reset_email, token_response
from rest_framework.parsers import FormParser
from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password,check_password
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie,csrf_protect
from django.views.decorators.csrf import csrf_exempt
from django.template.loader import get_template
from django.template import loader
from mytestwebsite.settings import TEMPLATES_BASE_URL
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.http import Http404
from django.utils import timezone
from datetime import timedelta
from rest_framework.exceptions import AuthenticationFailed




@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def request_otp(request):
    email = request.data.get('email')
    phone = request.data.get('phone')

    if email and phone:
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)

        if User.objects.filter(phone=phone).exists():
            return JsonResponse({'error': 'Phone already exists'}, status=400)

        return send_otp(phone)
    else:
        return JsonResponse({'error': 'Data missing'}, status=400)
    
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def resend_otp(request) : 
    phone = request.data.get('phone')
    if not phone : 
        return Response('data_missing',400)
    return send_otp(phone)


# Créer un objet logger
logger = logging.getLogger(__name__)
#tabda
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def verify_otp(request):
    try:
        phone = request.data.get('phone')
        otp = request.data.get('otp')

        print(f"Received OTP: {otp}")
        print(f"Received phone: {phone}")

        if not phone or not otp:
            return JsonResponse({'error': 'Phone or OTP missing in the request'}, status=400)

        otp_obj = get_object_or_404(Otp, phone=phone, verified=False)

        
            # Si la validité n'est pas définie, créez une validité de 10 minutes à partir du temps actuel
        validity_duration = timedelta(minutes=10)
        otp_obj.validity = timezone.now() + validity_duration
        otp_obj.save()

        # Utilisez make_aware pour ajouter le fuseau horaire par défaut
        validity_datetime = timezone.make_aware(datetime.datetime.combine(otp_obj.validity, datetime.datetime.now().time()))

        print(f"Validity datetime: {validity_datetime}")
        print(f"Current datetime: {timezone.now()}")

        
        if otp_obj.otp == int(otp):
            try:
                otp_obj.verified = True
                otp_obj.save()
                return JsonResponse({'message': 'otp_verified successfully'})
            except Exception as e:
                print(f"An error occurred during OTP verification: {e}")
                return JsonResponse({'error': 'Error during OTP verification'}, status=500)
        else:
            print("Incorrect otp")
            return JsonResponse({'error': 'Incorrect otp'}, status=400)

        
    except AuthenticationFailed as e:
        logger.error(f'Authentication failed: {e}', exc_info=True)
        return JsonResponse({'error': 'Authentication failed'}, status=401)
    except Http404:
        logger.error('Otp not found', exc_info=True)
        return JsonResponse({'error': 'Otp not found'}, status=404)
    except Exception as e:
        logger.error(f'Error in verify_otp: {e}', exc_info=True)
        print(f'ouni 3asba {e}')
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


@csrf_exempt
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def create_account(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))

            email = data.get('email')
            phone = data.get('phone')
            password = data.get('password')
            fullname = data.get('fullname')

            print(f"Received data - Email: {email}, Phone: {phone}, Password: {password}, Fullname: {fullname}")

            if email and phone and password and fullname:
                print(f"Trying to find Otp for phone: {phone}")
                otp_obj = get_object_or_404(Otp, phone=phone, verified=True)
                print(f"Found Otp: {otp_obj}")
                User.objects.create(email=email, phone=phone, fullname=fullname, password=password)
                otp_obj.delete()
                return JsonResponse({"message": "account created successfully"})
            else:
                error_message = "Invalid data provided. "
                if not email:
                    error_message += "Email is required. "
                if not phone:
                    error_message += "Phone is required. "
                if not password:
                    error_message += "Password is required. "
                if not fullname:
                    error_message += "Fullname is required. "

                print(f"Error message: {error_message.strip()}")

                return JsonResponse({"error": error_message.strip()}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format in the request body"}, status=400)

        except Exception as e:
            print(f"Error: {str(e)}")
            return JsonResponse({"error": "An error occurred while processing the request"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt 
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def login(request):
    email = request.data.get('email')
    phone = request.data.get('phone')
    password = request.data.get('password')

    if email:
        user = User.objects.filter(email=email).first()
        password1 = user.password if user else None
    elif phone:
        user = User.objects.filter(phone=phone).first()
        password1 = user.password if user else None
    else:
        return JsonResponse({'error': 'data missing'}, status=400)

    if user :
        if password == password1:
            return token_response(user)
        else :
            return JsonResponse({'response':'mdpincorrecte'})
    else:
        return JsonResponse({'error': 'incorrect password'}, status=400)
@api_view(['GET', 'POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_reset_email(request):
    if request.method == 'GET':
        # Logique pour gérer la méthode GET (afficher un formulaire, par exemple)
        return render(request, 'emails/reset-password.html')
    
    elif request.method == 'POST':
        email = request.data.get('email')
        if not email:
            return JsonResponse({'error': 'params_missing'}, status=400)

        user = get_object_or_404(User, email=email)
        send_password_reset_email(user)
        return JsonResponse({'message': 'password_reset_email_sent'}, status=200)
    
    return JsonResponse({'error': 'Method Not Allowed'}, status=405)

@api_view(['GET'])
def password_reset_form(request, email, token):
    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = loader.get_template('pages/link-expired.html').render()

    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            return render(request, 'pages/new-password-form.html', {
                'email': email,
                'token': token,
                'base_url': TEMPLATES_BASE_URL,
            })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)

    else:
        return HttpResponse(link_expired)
        
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_reset_confirm(request, email, token):
    email = request.data.get('email')
    token = request.data.get('token')
    password1 = request.data.get('password1')
    password2 = request.data.get('password2')
    print(password1)
    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = get_template('pages/link-expired.html').render()
    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            if len(password1) < 8:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password length must be at least 8'
                })

            if password1 == password2:
                user = token_instance.user
                User.objects.filter(email=user.email).update(password=password1)
                token_instance.delete()
                Token.objects.filter(user=user).delete()
                return redirect('password_updated')
            else:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password 1 must be equal to password 2'
                })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)
    else:
        return HttpResponse(link_expired)
@api_view(['GET'])
def password_updated(request) : 
    return render(request,'pages/password-updated.html')

@api_view(['GET'])
@permission_classes([IsAuthenticatedUser])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def userData(request) : 
    return Response()