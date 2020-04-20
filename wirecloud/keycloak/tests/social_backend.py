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

from copy import deepcopy
import json
import unittest

from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock

import django.dispatch


def signal_decorator(signal, sender=None):
    def mock_decorator(funct):
        def wrapper(sender, instance, created, **kwargs):
            funct(sender, instance, created)

        return wrapper
    return mock_decorator


class BaseOAuthMock():

    STRATEGY = None
    def __init__(self, strategy):
        self.STRATEGY = strategy

    def get_key_and_secret(self):
        return ('client', 'secret')


class KeycloakSocialAuthBackendTestCase(TestCase):

    IDM_SERVER = 'http://server'
    REALM = 'demo'
    KEY = 'rsa key'

    CLIENT_ID = 'client'
    SECRET = 'secret'

    TOKEN_INFO = {
        'preferred_username': 'username',
        'email': 'email@email.com',
        'name': 'user surname',
        'given_name': 'user',
        'family_name': 'surname'
    }

    DETAILS = {
        'username': 'username',
        'email': 'email@email.com',
        'fullname': 'user surname',
        'first_name': 'user',
        'last_name': 'surname',
        'is_superuser': False,
        'is_staff': False,
        'roles': []
    }

    def setUp(self):
        self._strategy = MagicMock()
        self._jwt = MagicMock()
        self._jwt.decode.return_value = 'user info'

        import django.conf
        self._old_settings = django.conf.settings
        self._settings = MagicMock(
            KEYCLOAK_SERVER=self.IDM_SERVER,
            KEYCLOAK_REALM=self.REALM,
            KEYCLOAK_KEY=self.KEY,
            SOCIAL_AUTH_KEYCLOAK_KEY=self.CLIENT_ID,
            SOCIAL_AUTH_KEYCLOAK_SECRET=self.SECRET,
            KEYCLOAK_GLOBAL_ROLE=False
        )

        django.conf.settings = self._settings

        # Mock post_save signal
        from django.dispatch import receiver
        self._receiver = receiver

        django.dispatch.receiver = signal_decorator

    def tearDown(self):
        import django.conf
        django.conf.settings = self._old_settings
        django.dispatch.receiver = self._receiver

    def _mock_module(self):
        from wirecloud.keycloak import social_auth_backend

        social_auth_backend.jwt = self._jwt

        social_auth_backend.settings = self._settings
        oauth2 = social_auth_backend.KeycloakOAuth2(self._strategy)
        return oauth2

    @patch('social_core.backends.oauth.BaseOAuth2', new=BaseOAuthMock)
    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_class_params(self):
        oauth2 = self._mock_module()

        self.assertEqual(oauth2.IDM_SERVER, 'http://server')
        self.assertEqual(oauth2.REALM, 'demo')
        self.assertEqual(oauth2.KEY, 'rsa key')

        self.assertEqual(oauth2.ACCESS_TOKEN_URL, 'http://server/auth/realms/demo/protocol/openid-connect/token')
        self.assertEqual(oauth2.AUTHORIZATION_URL, 'http://server/auth/realms/demo/protocol/openid-connect/auth')

    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_get_auth_headers(self):
        oauth2 = self._mock_module()
        headers = oauth2.auth_headers()

        self.assertEqual(headers, {
            'Authorization': 'Basic Y2xpZW50OnNlY3JldA=='
        })

    def _test_get_user_details(self, resource, expected_details, global_role=False):
        oauth2 = self._mock_module()
        details = oauth2.get_user_details(resource)

        self.assertEqual(details, expected_details)
        self.assertEquals(self._strategy, oauth2.STRATEGY)

    @patch('social_core.backends.oauth.BaseOAuth2', new=BaseOAuthMock)
    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_get_user_details_regular(self):
        self._test_get_user_details(self.TOKEN_INFO, self.DETAILS)

    @patch('social_core.backends.oauth.BaseOAuth2', new=BaseOAuthMock)
    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_get_user_details_admin(self):
        resource = deepcopy(self.TOKEN_INFO)
        details = deepcopy(self.DETAILS)

        resource['resource_access'] = {
            'client': {
                'roles': ['admin', 'manager']
            }
        }
        details['is_superuser'] = True
        details['is_staff'] = True
        details['roles'] = ['admin', 'manager']

        self._test_get_user_details(resource, details)

    @patch('social_core.backends.oauth.BaseOAuth2', new=BaseOAuthMock)
    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_get_user_details_admin_global(self):

        self._settings.KEYCLOAK_GLOBAL_ROLE = True
        resource = deepcopy(self.TOKEN_INFO)
        details = deepcopy(self.DETAILS)

        resource['realm_access'] = {
            'roles': ['admin']
        }
        details['is_superuser'] = True
        details['is_staff'] = True
        details['roles'] = ['admin']

        self._test_get_user_details(resource, details)

    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_get_user_info(self):
        oauth2 = self._mock_module()
        user_info = oauth2.user_data('token')

        self.assertEqual(user_info, 'user info')
        self._jwt.decode.assert_called_once_with('token', '-----BEGIN PUBLIC KEY-----\nrsa key\n-----END PUBLIC KEY-----', algorithms='RS256', audience='account')

    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_user_group_creation(self):
        group_model = MagicMock()
        instance = MagicMock()
        instance.social_auth.count.return_value = 1

        social_mock = MagicMock(extra_data={
            'roles': ['manager']
        })

        instance.social_auth.all.return_value = [social_mock]

        group_instance = MagicMock()
        group_model.objects.get_or_create.return_value = (group_instance, True)

        from wirecloud.keycloak import social_auth_backend

        social_auth_backend.get_group_model = MagicMock()
        social_auth_backend.get_group_model.return_value = group_model
        social_auth_backend.add_user_groups(MagicMock(), instance, True)

        # Check calls
        instance.social_auth.count.assert_called_once_with()
        instance.social_auth.all.assert_called_once_with()
        instance.groups.clear.assert_called_once_with()

        group_model.objects.get_or_create.assert_called_once_with(name='manager')
        instance.groups.add.assert_called_once_with(group_instance)


    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_user_group_no_social_profile(self):
        instance = MagicMock()
        instance.social_auth.count.return_value = 0

        from wirecloud.keycloak import social_auth_backend

        social_auth_backend.add_user_groups(MagicMock(), instance, True)

        instance.social_auth.count.assert_called_once_with()
        self.assertEqual(0, instance.social_auth.all.call_count)

    @patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
    @patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
    def test_user_group_remove_roles(self):
        group_model = MagicMock()
        instance = MagicMock()
        instance.social_auth.count.return_value = 1

        social_mock = MagicMock(extra_data={})
        instance.social_auth.all.return_value = [social_mock]

        from wirecloud.keycloak import social_auth_backend
        social_auth_backend.get_group_model = MagicMock()
        social_auth_backend.add_user_groups(MagicMock(), instance, True)

        instance.social_auth.count.assert_called_once_with()
        instance.social_auth.all.assert_called_once_with()
        instance.groups.clear.assert_called_once_with()

        self.assertEqual(0, social_auth_backend.get_group_model.call_count)

if __name__ == "__main__":
    unittest.main(verbosity=2)
