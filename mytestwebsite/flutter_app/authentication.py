from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import exceptions
from flutter_app.models import Token

class TokenAuthentication(BaseAuthentication) : 
    def authenticate(self, request):
        token = request.headers.get('Authorization')
        #print(str(token).split())
        if token : 
            try : 
                user = Token.objects.get(token = str(token).split()[1]).user
            except : 
                raise exceptions.AuthenticationFailed('unauthenticated_user')
        else : 
            user = None

        return user,None