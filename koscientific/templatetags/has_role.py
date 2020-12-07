from django import template
from django.shortcuts import get_object_or_404
from koscientific.models import *

register = template.Library() 

@register.filter(name='has_role') 
def has_role(user, role_name):
    role_choices = dict((v.lower(), k) for k, v in Role.ROLE_CHOICES)
    return user.roles.filter(id=role_choices[role_name]).exists()