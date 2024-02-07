from django.utils import timezone  # Assurez-vous d'importer correctement le module timezone
from django.db import models
from django.contrib.auth.models import AbstractUser, Group as DjangoGroup
from secure import PermissionsPolicy
from django.contrib.auth.hashers import make_password



class User( models.Model) : 
    email = models.EmailField()
    phone = models.CharField(max_length = 10) 
    fullname = models.CharField(max_length = 50)
    password = models.CharField(max_length = 5000)
    created_at = models.DateTimeField(auto_now_add = True)
    def __str__(self) : 
        return self.email
    def update_password(self, new_password):
        # Hasher le nouveau mot de passe avant la mise à jour
        hashed_password = make_password(new_password)
        User.objects.filter(pk=self.pk).update(password=hashed_password)
        
class Otp(models.Model) : 
    phone = models.CharField(max_length = 10)
    otp = models.IntegerField()
    validity = models.DateField(auto_now_add = True)
    verified = models.BooleanField(default = False)

    def __str__ (self) : 
        return self.phone
    

class Token(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(User, on_delete= models.CASCADE,related_name="tokens_set")
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.email
    
class PasswordResetToken(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    validity = models.DateTimeField(default=timezone.now) 
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.email
