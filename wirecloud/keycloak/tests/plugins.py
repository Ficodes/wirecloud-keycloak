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

import unittest
from importlib import reload

from unittest import TestCase
from unittest.mock import patch, MagicMock


class WirecloudPluginMock():
    pass


def translation_mock(text):
    return text


class KeycloakPluginTestCase(TestCase):

    KEY = 'key'
    SECRET = 'secret'
    _backend = None

    def setUp(self):
        self._wirecloud_plugin = MagicMock()
        self._backend = MagicMock()

    @patch('wirecloud.platform.plugins.WirecloudPlugin', new=WirecloudPluginMock)
    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(
            'wirecloud.keycloak',
            'social_django'
        ), SOCIAL_AUTH_KEYCLOAK_KEY=KEY, SOCIAL_AUTH_KEYCLOAK_SECRET=SECRET))
    @patch('wirecloud.keycloak.utils.build_backend', new=MagicMock())
    @patch('django.utils.translation.ugettext_lazy')
    def test_get_urls(self, translation_mock):

        import wirecloud.keycloak.utils
        version_hash_mock = MagicMock(return_value=MagicMock(return_value='1'))
        wirecloud.keycloak.utils.build_version_hash = version_hash_mock

        oauth_discovery = MagicMock()
        import wirecloud.keycloak.views
        wirecloud.keycloak.views.oauth_discovery = oauth_discovery

        # Mock URL
        url_mock = MagicMock(return_value='/url/')
        import django.conf.urls
        django.conf.urls.url = url_mock

        # Mock cache
        cache_proc = MagicMock(return_value='cache')
        cache_mock = MagicMock(return_value=cache_proc)

        import django.views.decorators.cache
        django.views.decorators.cache.cache_page = cache_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        urls = plugin.get_urls()

        self.assertEqual(('/url/',), urls)

        # Validate calls
        cache_mock.assert_called_once_with(7 * 24 * 60 * 60, key_prefix='well-known-oauth-1')
        cache_proc.assert_called_once_with(oauth_discovery)

        url_mock.assert_called_once_with('^.well-known/oauth$', 'cache', name='oauth.discovery')

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(), SOCIAL_AUTH_KEYCLOAK_KEY=KEY, SOCIAL_AUTH_KEYCLOAK_SECRET=SECRET))
    def test_get_urls_not_enabled(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        urls = plugin.get_urls()

        self.assertEqual((), urls)

    @patch('wirecloud.keycloak.utils.get_social_auth_model')
    def test_get_api_backends(self, social_model_mock):
        user_mock = MagicMock()
        social_mock = MagicMock()
        social_mock.objects.get.return_value = MagicMock(user=user_mock)
        social_model_mock.return_value = social_mock

        import wirecloud.keycloak.utils
        version_hash_mock = MagicMock(return_value=MagicMock(return_value='1'))
        wirecloud.keycloak.utils.build_version_hash = version_hash_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True
        user_data_mock = MagicMock()
        user_data_mock.user_data.return_value = {
            'username': 'user'
        }
        wirecloud.keycloak.plugins.KEYCLOAK_SOCIAL_AUTH_BACKEND = user_data_mock

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        token = plugin.get_api_auth_backends()

        self.assertEqual(user_mock, token['Bearer']('bearer', 'token'))

        social_mock.objects.get.assert_called_once_with(provider='keycloak', uid='user')
        user_data_mock.user_data.assert_called_once_with('token')

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(), SOCIAL_AUTH_KEYCLOAK_KEY=KEY, SOCIAL_AUTH_KEYCLOAK_SECRET=SECRET))
    def test_get_api_backends_not_enabled(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        token = plugin.get_api_auth_backends()
        self.assertEqual({}, token)

    def test_get_constants(self):
        import wirecloud.keycloak.utils
        version_hash_mock = MagicMock(return_value=MagicMock(return_value='1'))
        wirecloud.keycloak.utils.build_version_hash = version_hash_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        backend_mock = MagicMock(IDM_SERVER='http://idm.docker')
        wirecloud.keycloak.plugins.KEYCLOAK_SOCIAL_AUTH_BACKEND = backend_mock

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()
        const = plugin.get_constants()

        self.assertEqual({
            'KEYCLOAK_SERVER': 'http://idm.docker'
        }, const)


    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=()))
    def test_get_constants_not_enabled(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()
        const = plugin.get_constants()

        self.assertEqual({}, const)

    def test_get_proxy_processors(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()
        proc = plugin.get_proxy_processors()

        self.assertEqual(('wirecloud.keycloak.proxy.IDMTokenProcessor',), proc)

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=()))
    def test_get_proxy_processors_not_enabled(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()
        proc = plugin.get_proxy_processors()

        self.assertEqual((), proc)

    @patch('django.utils.translation.ugettext_lazy', new=translation_mock)
    def test_get_platform_context_definitions(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()
        self.assertEqual({
            'fiware_token_available': {
                'label': 'FIWARE token available',
                'description': 'Indicates if the current user has associated a FIWARE auth token that can be used for accessing other FIWARE resources',
            },
        }, plugin.get_platform_context_definitions())

    def test_get_platform_context_current_values_django1(self):
        user_mock = MagicMock()
        user_mock.is_authenticated.return_value = True
        social_mock = MagicMock()
        social_mock.exists.return_value = True
        user_mock.social_auth.filter.return_value = social_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        self.assertEqual({
            'fiware_token_available': True
        }, plugin.get_platform_context_current_values(user_mock))
        user_mock.is_authenticated.assert_called_once_with()
        user_mock.social_auth.filter.assert_called_once_with(provider='keycloak')
        social_mock.exists.assert_called_once_with()

    def test_get_platform_context_current_values(self):
        user_mock = MagicMock()
        user_mock.is_authenticated = True
        social_mock = MagicMock()
        social_mock.exists.return_value = True
        user_mock.social_auth.filter.return_value = social_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        self.assertEqual({
            'fiware_token_available': True
        }, plugin.get_platform_context_current_values(user_mock))
        user_mock.social_auth.filter.assert_called_once_with(provider='keycloak')
        social_mock.exists.assert_called_once_with()

    def test_get_platform_context_current_values_not_enabled(self):
        user_mock = MagicMock()
        user_mock.is_authenticated = True
        social_mock = MagicMock()
        social_mock.exists.return_value = True
        user_mock.social_auth.filter.return_value = social_mock

        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = False
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        self.assertEqual({
            'fiware_token_available': False
        }, plugin.get_platform_context_current_values(user_mock))

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(
            'wirecloud.keycloak',
            'social_django'
        ), SOCIAL_AUTH_KEYCLOAK_KEY=KEY, SOCIAL_AUTH_KEYCLOAK_SECRET=SECRET, KEYCLOAK_SERVER='http://idm.docker'))
    def test_get_django_template_context_processors(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = True
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        processors = plugin.get_django_template_context_processors()
        self.assertEqual({
            'KEYCLOAK_SERVER': 'http://idm.docker',
        }, processors)

    def test_get_django_template_context_processors_not_enabled(self):
        import wirecloud.keycloak.plugins
        reload(wirecloud.keycloak.plugins)

        wirecloud.keycloak.plugins.IDM_SUPPORT_ENABLED = False
        plugin = wirecloud.keycloak.plugins.KeycloakPlugin()

        processors = plugin.get_django_template_context_processors()
        self.assertEqual({
            'KEYCLOAK_SERVER': None,
        }, processors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
