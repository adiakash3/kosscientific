from django.shortcuts import render
from koscientific.models import *
from django.http import HttpResponse, Http404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import *
from .pagination import *
from django.db.models import Q
from rest_framework import status

paginator = MyPagination()


def Test(request):
    return HttpResponse('Here it is tested')


@api_view(['GET'])
def Testapi(request):
    return HttpResponse('hii hello')


@api_view(['GET'])
def MemberList(request):
    member = MemberShip.objects.all().order_by('user__first_name')
    search = request.GET.get('search')
    if search != '' and search is not None:
        query_data = member.filter(Q(user__first_name__icontains=search) | Q(user__last_name__icontains=search) |
                                   Q(kos_no__icontains=search)).distinct()

        page = paginator.paginate_queryset(query_data, request)
        serializer = MemberSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    else:

        page = paginator.paginate_queryset(member, request)
        serializer = MemberSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
