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
import types

from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock


class WirecloudPluginMock():
    pass


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

        from wirecloud.keycloak.plugins import KeycloakPlugin
        plugin = KeycloakPlugin()

        urls = plugin.get_urls()

        self.assertEqual(('/url/',), urls)

        # Validate calls
        cache_mock.assert_called_once_with(7 * 24 * 60 * 60, key_prefix='well-known-oauth-1')
        cache_proc.assert_called_once_with(oauth_discovery)

        url_mock.assert_called_once_with('^.well-known/oauth$', 'cache', name='oauth.discovery')

    def test_get_urls_not_enabled(self):
        pass

    def test_get_api_backends(self):
        pass

    def test_get_api_backends_not_enabled(self):
        pass

    def test_get_constants(self):
        pass

    def test_get_constants_not_enabled(self):
        pass

    def test_get_proxy_processors(self):
        pass

    def test_get_proxy_processors_not_enabled(self):
        pass

    def test_get_platform_context_definitions(self):
        pass

    def test_get_platform_context_definitions_not_enabled(self):
        pass

    def test_get_platform_context_current_values(self):
        pass

    def test_get_platform_context_current_values_not_enabled(self):
        pass

    def test_get_django_template_context_processors(self):
        pass

    def test_get_django_template_context_processors_not_enabled(self):
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)