import os
import jwt

from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.contrib.auth import get_user_model

from datetime import timedelta
from dotenv import load_dotenv

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView

from project.apps.authentication.models import BlacklistedToken
from project.apps.authentication.serializers import UserSerializer
from project.settings import settings
from project.apps.authentication.utils import generate_access_token, generate_refresh_token

load_dotenv()


# Create your views here.


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    '''
    To obtain a new access_token this view expects 2 important things:
        1. a cookie that contains a valid refresh_token
        2. a header 'X-CSRFTOKEN' with a valid csrf token, client app can get it from cookies "csrftoken"
    '''

    User = get_user_model()
    refresh_token = request.COOKIES.get('refresh')

    if BlacklistedToken.objects.filter(token=refresh_token).exists():
        raise exceptions.AuthenticationFailed('Token is already blacklisted.')

    if refresh_token is None:
        raise exceptions.AuthenticationFailed(
            'Authentication credentials were not provided.')
    try:
        payload = jwt.decode(
            refresh_token, str(os.getenv('REFRESH_SECRET_KEY')), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed(
            'expired refresh token, please login again.')

    user = User.objects.filter(id=payload.get('user_id')).first()
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('user is inactive')

    access_token = generate_access_token(user)
    return Response({'access': access_token})


@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):
    User = get_user_model()
    # username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    response = Response()

    if (email is None) or (password is None):
        raise exceptions.AuthenticationFailed(
            'Username and password required')

    user = User.objects.filter(email=email).first()

    if user is None:
        raise exceptions.AuthenticationFailed('User not found')
    if not user.check_password(password):
        raise exceptions.AuthenticationFailed('Wrong password')

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    response.set_cookie(
        key="access",
        value=access_token,
        httponly=True,
        expires=timedelta(seconds=5),
        samesite='Strict',
        secure=True
    )
    response.set_cookie(
        key='refresh',
        value=refresh_token,
        httponly=True,
        expires=timedelta(minutes=5),
        samesite='Strict',
        secure=True
    )
    # response.data = {
    #     'access': access_token,
    #     'user': serialized_user
    # }
    response.data = {
        'user': serialized_user
    }
    response.status_code = status.HTTP_200_OK

    return response

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    token = request.COOKIES.get('refresh')

    if token:
        BlacklistedToken.objects.create(token=token)
        response = Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

        response.delete_cookie('access')
        response.delete_cookie('refresh')

        return response
    else:
        return Response({'error': 'Token not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([AllowAny])
def access_token_view(request):
    # Получаем токен из cookies
    token = request.COOKIES.get('access')

    if token:
        return Response({'access': token}, status=200)
    else:
        return Response({'error': 'Token not found'}, status=404)

@api_view(['GET'])
def get_user(request):
    user = request.user
    serialized_user = UserSerializer(user).data
    return Response({'user': serialized_user})
