from django.shortcuts import render
import random
import string
import json
import binascii
from django.contrib.auth.models import User
from django.http.response import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
import base64
from django.utils.translation import ugettext_lazy as _
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework import HTTP_HEADER_ENCODING
from .serializers import *
# Create your views here.


def authorized(request):
    auth = get_authorization_header(request).split()
    if not auth or auth[0].lower() != b'basic':
        msg = _("Not basic authentication.")
        result = {'status': False, 'message': msg}
        return result
    if len(auth) == 1:
        msg = _('Invalid basic header. No credentials provided.')
        result = {'status': False, 'message': msg}
        return result
    elif len(auth) > 2:
        msg = _('Invalid basic header. Credentials string should not contain spaces.')
        result = {'status': False, 'message': msg}
        return result
    try:
        auth_parts = base64.b64decode(auth[1]).decode(
            HTTP_HEADER_ENCODING).partition(':')
    except (TypeError, UnicodeDecodeError, binascii.Error):
        msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
        result = {'status': False, 'message': msg}
        return result

    userid, password = auth_parts[0], auth_parts[2]
    # Your auth table specific codes
    if 'iresto' == userid and '026866326a9d1d2b23226e4e8929192g' == password:  # my dummy code
        result = {'status': True, 'message': ""}
        return result
    else:
        msg = _('User not found.')
        result = {'status': False, 'message': msg}
        return result

# ===============================USER API'S=====================================


@csrf_exempt
def user_login(request):
    result = authorized(request)
    if result['status'] == True:
        tok = MyTokenObtainPairSerializer()  # object to get user token
        if request.method == 'POST':
            phone = request.POST.get('phone')
            block = User.objects.filter(phone=phone).values('is_block')
            try:
                users = User.objects.get(phone=phone)
                id = User.objects.filter(phone=phone).values('id')
                block = User.objects.filter(phone=phone).values('is_block')
                block1 = block[0]
            except:
                users = None
            if users is not None and block1['is_block'] == False:
                users_serializer = UserSerializer(users)
                token = tok.get_token(users)
                otp = random.randint(1111, 9999)
                id1 = id[0]
                otp_entry = User.objects.filter(id=id1['id']).update(otp=otp)
                return JsonResponse(
                    {'message': 'User logged in successfully!', 'data': users_serializer.data,
                     'otp': otp})
            else:
                S = 10
                username = ''.join(random.choices(
                    string.ascii_uppercase + string.digits, k=S))
                otp = random.randint(1111, 9999)
                try:
                    user = User.objects.create_user(username=str(username),
                                                    password="herk12354312",
                                                    phone=phone,
                                                    otp=otp,
                                                    )
                    user.save()
                    id1 = user.id
                    users = User.objects.get(id=id1)
                    token = tok.get_token(users)
                    stoken = str(token)
                    users_serializer = UserSerializer(users)
                    return JsonResponse(
                        {'status': True, 'message': 'User logged in successfully!', 'data': users_serializer.data,
                         'otp': otp})
                except:
                    return JsonResponse(
                        {'status': True, 'message': 'You have been blocked by admin', })
    return JsonResponse({"message": "Unauthorised User", })
