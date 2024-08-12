import os
import jwt

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from django.middleware.csrf import CsrfViewMiddleware
from django.contrib.auth import get_user_model

from dotenv import load_dotenv

load_dotenv()


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return the failure reason instead of an HttpResponse
        return reason


def dummy_get_response():  # pragma: no cover
    return None


class SafeJWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        User = get_user_model()
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            return None

        try:
            access_token = authorization_header.split(" ")[1]
            payload = jwt.decode(access_token, str(os.getenv('ACCESS_SECRET_KEY')), algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('access_token expired')
        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')

        user = User.objects.filter(id=payload['user_id']).first()

        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User is inactive')

        self.enforce_csrf(request)

        return user, None

    def enforce_csrf(self, request):
        check = CSRFCheck(dummy_get_response)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        print(reason)
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)


