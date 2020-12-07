from django import template
from num2words import num2words

register = template.Library() 

@register.filter(name='divide') 
def divide(value, arg):
    try:
        return round(float(value) / float(arg),2)
    except (ValueError, ZeroDivisionError):
        return None
    
    
@register.filter(name='add') 
def add(value, arg):
    try:
        return int(value) + int(arg)
    except (ValueError, ZeroDivisionError):
        return None
    
    
@register.filter(name='num2words') 
def add(value):
    try:
        return num2words(value)
    except Exception as e:
        return value