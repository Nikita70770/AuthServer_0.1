import os
import jwt

from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.contrib.auth import get_user_model

from datetime import timedelta
from dotenv import load_dotenv

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated

from project.apps.authentication.models import BlacklistedToken
from project.apps.authentication.serializers import UserSerializer
from project.apps.authentication.utils import generate_access_token, generate_refresh_token

load_dotenv()


# Create your views here.

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    User = get_user_model()
    refresh_token = request.COOKIES.get('refresh')

    if BlacklistedToken.objects.filter(token=refresh_token).exists():
        return Response({'detail': 'Токен уже занесен в черный список.'}, status=status.HTTP_400_BAD_REQUEST)

    if not refresh_token:
        return Response({'detail': 'Токен обновления отсутствует.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        payload = jwt.decode(
            refresh_token, str(os.getenv('REFRESH_SECRET_KEY')), algorithms=['HS256'])

        user = User.objects.filter(id=payload.get('user_id')).first()

        if user is None:
            return Response({'detail': 'Пользователь не найден.'}, status=status.HTTP_404_NOT_FOUND)
        if not user.is_active:
            return Response({'detail': 'Пользователь неактивен.'}, status=status.HTTP_404_NOT_FOUND)

        access_token = generate_access_token(user)
        response = Response({'access': access_token}, status=status.HTTP_200_OK)
        return response

    except jwt.ExpiredSignatureError:
        BlacklistedToken.objects.create(token=refresh_token)
        response = Response({'detail': 'Токен обновления истек.'}, status=status.HTTP_401_UNAUTHORIZED)
        response.delete_cookie('access')
        response.delete_cookie('refresh')
        return response


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
        return Response({'detail': 'Поля логин и пароль обязательны для заполнения.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email=email).first()

    if user is None:
        return Response({'detail': 'Пользователь не найден.'}, status=status.HTTP_404_NOT_FOUND)
    if not user.check_password(password):
        return Response({'detail': 'Неверный пароль.'}, status=status.HTTP_400_BAD_REQUEST)

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    response.set_cookie(
        key='refresh',
        value=refresh_token,
        httponly=True,
        expires=timedelta(seconds=10),
        samesite='Strict',
        secure=True
    )
    response.data = {
        'access': access_token,
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
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user
    serialized_user = UserSerializer(user).data
    return Response({'user': serialized_user}, status=status.HTTP_200_OK)
