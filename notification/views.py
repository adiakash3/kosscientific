from django.shortcuts import render
from  .models import *
from django.template.loader import render_to_string
from  django.http import HttpResponse

# Create your views here.

# @login_required
def update_notification(request):
    # make all user message to readed once drop down open
    Message.objects.filter(user=request.user).update(is_readed=True)

    context = {
        'messages': Message.objects.filter(user=request.user).order_by('-created_at')[:5],
        'message_count': Message.objects.filter(user=request.user).count(),
    }
    html = render_to_string('main/notification.html', context)
    return HttpResponse(html)
