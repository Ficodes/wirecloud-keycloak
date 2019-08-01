# -*- coding: utf-8 -*-

# Copyright (c) 2019 Future Internet Consulting and Development Solutions S.L.

# This file is part of Wirecloud Keycloak plugin.

# Wirecloud is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Wirecloud is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with Wirecloud.  If not, see <http://www.gnu.org/licenses/>.

import json
from importlib import reload

from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock


def get_decorator(func):
    def dec(request):
        return func(request)

    return dec


class KeycloakViewTestCase(TestCase):

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=()))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_oauth_discovery(self):
        from wirecloud.keycloak import views
        reload(views)

        backend_mock = MagicMock()
        backend_mock.AUTHORIZATION_URL = 'https://keycloak.com/auth'
        backend_mock.ACCESS_TOKEN_URL = 'https://keycloak.com/token'

        views.build_simple_backend = MagicMock(return_value=backend_mock)
        views.get_absolute_reverse_url = MagicMock(return_value='/login')

        response_mock = MagicMock()
        views.HttpResponse = MagicMock(return_value=response_mock)

        request = MagicMock()
        response = views.oauth_discovery(request)

        # Validate response
        self.assertEqual(response_mock, response)

        # Validate calls
        views.get_absolute_reverse_url.assert_called_once_with('oauth.default_redirect_uri', request)
        views.HttpResponse.assert_called_once_with(json.dumps({
            'flows': ["Authorization Code Grant", "Resource Owner Password Credentials Grant"],
            'auth_endpoint': 'https://keycloak.com/auth',
            'token_endpoint':'https://keycloak.com/token',
            'default_redirect_uri': '/login',
            'version': '2.0',
        }, sort_keys=True), content_type='application/json; charset=UTF-8')

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=()))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_login(self):
        from wirecloud.keycloak import views
        reload(views)

        response_mock = MagicMock()
        views.HttpResponseRedirect = MagicMock(return_value=response_mock)
        views.REDIRECT_FIELD_NAME = 'field'

        request = MagicMock()
        request.user.is_authenticated.return_value = True
        request.GET.get.return_value = '/home'

        response = views.login(request)

        self.assertEqual(response_mock, response)
        request.user.is_authenticated.assert_called_once_with()
        request.GET.get.assert_called_once_with('field', '/')
        views.HttpResponseRedirect.assert_called_once_with('/home')

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=()))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_login_not_authenticated(self):
        from wirecloud.keycloak import views
        reload(views)

        response_mock = MagicMock()
        views.HttpResponseRedirect = MagicMock(return_value=response_mock)

        request = MagicMock()
        request.user.is_authenticated.return_value = False
        views.reverse = MagicMock(return_value='/home')
        request.GET.urlencode.return_value = 'setting=test'

        response = views.login(request)

        self.assertEqual(response_mock, response)
        request.user.is_authenticated.assert_called_once_with()
        request.GET.urlencode.assert_called_once_with()
        views.reverse.assert_called_once_with('social:begin', kwargs={'backend': 'keycloak'})
        views.HttpResponseRedirect.assert_called_once_with('/home?setting=test')

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=()))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_logout(self):
        from wirecloud.keycloak import views
        reload(views)

        views.wirecloud_logout = MagicMock()

        request = MagicMock()
        request.META = ()
        response = views.logout(request)

        views.wirecloud_logout.assert_called_once_with(request)
        self.assertEqual(views.wirecloud_logout(), response)

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=({'url':'http://keycloak.com'},)))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_logout_external_domain(self):
        from wirecloud.keycloak import views
        reload(views)

        views.wirecloud_logout = MagicMock(return_value={})

        request = MagicMock()
        request.META = {
            'HTTP_ORIGIN': 'http://keycloak.com'
        }
        response = views.logout(request)

        self.assertEqual({
            'Access-Control-Allow-Origin': 'http://keycloak.com',
            'Access-Control-Allow-Credentials': 'true'
        }, response)

        views.wirecloud_logout.assert_called_once_with(request, next_page=None)

    @patch('django.conf.settings', new=MagicMock(FIWARE_PORTALS=()))
    @patch('django.views.decorators.http.require_GET', new=get_decorator)
    def test_logout_unauthorized(self):
        from wirecloud.keycloak import views
        reload(views)

        response_mock = MagicMock()
        views.build_error_response = MagicMock(return_value=response_mock)

        request = MagicMock()
        request.META = {
            'HTTP_ORIGIN': 'http://keycloak.com'
        }
        response = views.logout(request)

        self.assertEqual(response_mock, response)
        views.build_error_response.assert_called_once_with(request, 403, '')
