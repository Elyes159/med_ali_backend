import uuid
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
    

class Category(models.Model) : 
    name = models.CharField(max_length=50)
    position = models.IntegerField(default = 0)
    image = models.ImageField(upload_to='categories/')
    def __str__(self) : 
        return self.name
    

class SLide(models.Model) : 
    position = models.IntegerField(default = 0)
    image = models.ImageField(upload_to='categories/')

class Product(models.Model) : 
    id = models.UUIDField(primary_key=True,default = uuid.uuid4,editable=False ) 
    category = models.ForeignKey(Category,on_delete = models.CASCADE,related_name = 'products_set')
    title = models.CharField(max_length= 500)
    description = models.TextField(max_length = 100000)
    price = models.IntegerField(default = 0)
    offer_price = models.IntegerField(default = 0)
    delivery_charge = models.IntegerField(default = 0)
    star_5 = models.IntegerField(default = 0)
    star_4 = models.IntegerField(default = 0)
    star_3 = models.IntegerField(default = 0)
    star_2 = models.IntegerField(default = 0)
    star_1 = models.IntegerField(default = 0)
    cod = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) : 
        return self.title
    

class ProductOption(models.Model) : 
    id = models.UUIDField(primary_key=True,default = uuid.uuid4,editable=False ) 
    product = models.ForeignKey(Product,on_delete = models.CASCADE,related_name='options_set')
    option = models.CharField(max_length = 50)
    quantity = models.IntegerField(default = 0)

    def __str__(self) : 
        return f"({self.option})  {self.product.title}"
    

class ProductImage(models.Model) : 
    position = models.IntegerField(default=0)
    image = models.ImageField(upload_to='products/')
    product_option = models.ForeignKey(ProductOption,on_delete = models.CASCADE,related_name='product_images_set')

class PageItem(models.Model) : 
    position = models.IntegerField
    image = models.ImageField(upload_to='product/')
    category = models.ForeignKey(Category,on_delete = models.CASCADE,related_name = 'pageitems_set')
    choices = [
        (1,'BANNER'),
        (2,'SWIPER'),
        (3,'GRID'),
    ]
    viewtype = models.IntegerField(choices = choices)
    title = models.CharField(max_length = 50)
    product_options = models.ManyToManyField(ProductOption,blank=True)

    def __str__(self) : 
        return self.category.name


