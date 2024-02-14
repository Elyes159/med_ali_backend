from django.contrib import admin
from django.contrib.admin import register

from flutter_app.models import Category, Otp, PageItem, PasswordResetToken, Product, ProductImage, ProductOption, SLide, Token, User
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


@register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display  = ['name','position','image']

@register(SLide)
class CategoryAdmin(admin.ModelAdmin):
    list_display  = ['position','image']



class ProductOptionInline(admin.TabularInline) : 
    list  = ['id','product','option','quantity']
    model = ProductOption


@register(Product)
class ProductAdmin(admin.ModelAdmin):

    inlines = [ProductOptionInline]

    list_display  = ['id','category','title','price','offer_price','delivery_charge','cod','created_at','updated_at']


class ProductImageInline(admin.TabularInline) : 
    list = ['image','position']
    model = ProductImage


@register(ProductOption)
class ProductOptionAdmin(admin.ModelAdmin):
    inlines = [ProductImageInline]
    list_display=['id','product','option','quantity']


@register(PageItem)
class PageItemAdmin(admin.ModelAdmin):
    list_display=['id','title','position','image','category','viewtype']



