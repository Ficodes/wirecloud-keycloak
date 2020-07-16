# -*- coding: utf-8 -*-

# Copyright (c) 2019-2020 Future Internet Consulting and Development Solutions S.L.

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
import unittest

from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock


def signal_decorator(signal, sender=None):
    def mock_decorator(funct):
        def wrapper(sender, instance, created, **kwargs):
            funct(sender, instance, created)

        return wrapper
    return mock_decorator


class BaseOAuthMock():

    STRATEGY = None
    SETTINGS = {}

    def __init__(self, strategy):
        self.STRATEGY = strategy

    def auth_complete_params(self, state=None):
        return {}

    def setting(self, key, default=None):
        return self.SETTINGS.get(key, default)

    def get_key_and_secret(self):
        return ('client', 'secret')


@patch('social_core.backends.oauth.BaseOAuth2', new=BaseOAuthMock)
@patch('wirecloud.keycloak.utils.get_user_model', new=MagicMock())
@patch('wirecloud.keycloak.utils.get_group_model', new=MagicMock())
class KeycloakSocialAuthBackendTestCase(TestCase):

    URL = 'http://server'
    REALM = 'demo'

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

        import django.conf
        self._old_settings = django.conf.settings
        self._settings = MagicMock(
            SOCIAL_AUTH_KEYCLOAK_OIDC_URL=self.URL,
            SOCIAL_AUTH_KEYCLOAK_OIDC_REALM=self.REALM,
            SOCIAL_AUTH_KEYCLOAK_OIDC_KEY=self.CLIENT_ID,
            SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET=self.SECRET,
            SOCIAL_AUTH_KEYCLOAK_OIDC_GLOBAL_ROLE=False
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

        social_auth_backend.settings = self._settings
        return social_auth_backend.KeycloakOpenIdConnect(self._strategy)

    def test_eauth_complete_params(self):
        backend = self._mock_module()
        backend.strategy = Mock(
            request=Mock(
                session=Mock(
                    session_key="a-session-id"
                )
            )
        )
        params = backend.auth_complete_params()

        self.assertEqual(params["client_session_state"], "a-session-id")

    def test_class_params(self):
        backend = self._mock_module()

        self.assertEqual(backend.URL, 'http://server')
        self.assertEqual(backend.REALM, 'demo')
        self.assertEqual(backend.OIDC_ENDPOINT, 'http://server/auth/realms/demo')

    def _test_get_user_details(self, id_token, resource, expected_details, global_role=False):
        backend = self._mock_module()
        backend.id_token = id_token
        details = backend.get_user_details(resource)

        self.assertEqual(details, expected_details)
        self.assertEquals(self._strategy, backend.STRATEGY)

    def test_get_user_details_regular(self):
        self._test_get_user_details(self.TOKEN_INFO, self.TOKEN_INFO, self.DETAILS)

    def test_get_user_details_admin(self):
        id_token = deepcopy(self.TOKEN_INFO)
        resource = deepcopy(self.TOKEN_INFO)
        details = deepcopy(self.DETAILS)

        id_token['resource_access'] = {
            'client': {
                'roles': ['admin', 'manager']
            }
        }
        details['is_superuser'] = True
        details['is_staff'] = True
        details['roles'] = ['admin', 'manager']

        self._test_get_user_details(id_token, resource, details)

    def test_get_user_details_admin_global(self):

        self._settings.SOCIAL_AUTH_KEYCLOAK_OIDC_GLOBAL_ROLE = True
        id_token = deepcopy(self.TOKEN_INFO)
        resource = deepcopy(self.TOKEN_INFO)
        details = deepcopy(self.DETAILS)

        id_token['realm_access'] = {
            'roles': ['admin']
        }
        details['is_superuser'] = True
        details['is_staff'] = True
        details['roles'] = ['admin']

        self._test_get_user_details(id_token, resource, details)

    def test_end_session_url_from_dynamic_config(self):
        backend = self._mock_module()
        backend.oidc_config = Mock(return_value={"end_session_endpoint": "an/endpoint"})
        url = backend.end_session_url()

        self.assertEqual(url, "an/endpoint")

    def test_end_session_url_from_override(self):
        backend = self._mock_module()
        backend.END_SESSION_URL = "another/endpoint"
        url = backend.end_session_url()

        self.assertEqual(url, "another/endpoint")

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

    def test_user_group_no_social_profile(self):
        instance = MagicMock()
        instance.social_auth.count.return_value = 0

        from wirecloud.keycloak import social_auth_backend

        social_auth_backend.add_user_groups(MagicMock(), instance, True)

        instance.social_auth.count.assert_called_once_with()
        self.assertEqual(0, instance.social_auth.all.call_count)

    def test_user_group_remove_roles(self):
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

    @patch("wirecloud.keycloak.social_auth_backend.jwk")
    @patch("wirecloud.keycloak.social_auth_backend.jwt")
    def test_parse_incomming_data(self, jwt, jwk):
        backend = self._mock_module()
        backend.find_valid_key = Mock(
            return_value={
                "alg": "RS256",
            }
        )
        data = backend.parse_incomming_data("encrypted_data")

        self.assertEqual(data, jwt.decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
