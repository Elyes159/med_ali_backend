from rest_framework import serializers
from rest_framework.serializers import ModelSerializer

from flutter_app.models import Category, PageItem, Product, ProductImage, ProductOption, SLide, User

class UserSerializer(ModelSerializer) : 
    class Meta:
        model = User
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer) : 
    class Meta : 
        model = Category
        fields = ['name','position','image']


class SLideSerializer(serializers.ModelSerializer) : 
    class Meta : 
        model = SLide
        fields = ['position','image']

class ProductSerializer(ModelSerializer) : 
    class Meta : 
        model = Product
        fields = ['__all__']


class ProductOptionSerializer(ModelSerializer) : 
    class Meta : 
        model = ProductOption
        fields = ['__all__']


class ProductImageSerializer(ModelSerializer) : 
    class Meta:
        model = ProductImage
        fields = ['__all__']


class PageItemSerializer(ModelSerializer) : 
    class Meta:
        model = PageItem
        fields = ['__all__']
