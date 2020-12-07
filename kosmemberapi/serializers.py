from rest_framework import serializers
from koscientific.models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=('first_name','last_name')

class MemberSerializer(serializers.ModelSerializer):
    user=UserSerializer()
    class Meta:
        model= MemberShip
        fields=('kos_no' , 'user')
        depth=1
