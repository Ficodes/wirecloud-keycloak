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

from importlib import reload

import unittest
from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock


def translation_mock(text):
    return text


class IDMTokenProcessorTestCase(TestCase):

    def _text_proxy_processor(self, request):
        import wirecloud.keycloak.proxy
        reload(wirecloud.keycloak.proxy)

        wirecloud.keycloak.proxy._ = translation_mock
        self._strategy = MagicMock()
        wirecloud.keycloak.proxy.STRATEGY = self._strategy

        processor = wirecloud.keycloak.proxy.IDMTokenProcessor()
        processor.process_request(request)

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(
            'wirecloud.keycloak',
            'social_django'
        ), SOCIAL_AUTH_KEYCLOAK_KEY='key', SOCIAL_AUTH_KEYCLOAK_SECRET='secret'))
    @patch('wirecloud.keycloak.utils.build_backend', new=MagicMock())
    @patch('wirecloud.keycloak.utils.build_version_hash', new=MagicMock())
    @patch('wirecloud.keycloak.utils.load_strategy', new=MagicMock())
    def test_proxy_no_headers(self):
        request = {
            'headers': []
        }

        from wirecloud.keycloak.proxy import IDMTokenProcessor
        processor = IDMTokenProcessor()

        processor.process_request(request)

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(
            'wirecloud.keycloak',
            'social_django'
        ), SOCIAL_AUTH_KEYCLOAK_KEY='key', SOCIAL_AUTH_KEYCLOAK_SECRET='secret'))
    @patch('wirecloud.keycloak.utils.build_backend', new=MagicMock())
    @patch('wirecloud.keycloak.utils.build_version_hash', new=MagicMock())
    @patch('wirecloud.keycloak.utils.load_strategy', new=MagicMock())
    def test_proxy_user_source_token(self):
        oauth_info = MagicMock(access_token='token')
        oauth_info.access_token_expired.return_value = False

        user = MagicMock()
        user.social_auth.get.return_value = oauth_info

        request = {
            'user': user,
            'headers': {
                'fiware-oauth-token': 'token1',
                'fiware-oauth-header-name': 'Authorization'
            },
            'workspace': {}
        }

        self._text_proxy_processor(request)

        # Validate oauth info calls
        user.social_auth.get.assert_called_once_with(provider='keycloak')
        oauth_info.access_token_expired.assert_called_once_with()
        self.assertEqual(0, oauth_info.refresh_token.call_count)

        # Validate headers
        self.assertEqual({
            'Authorization': 'Bearer token'
        }, request['headers'])

    @patch('django.conf.settings', new=MagicMock(INSTALLED_APPS=(
            'wirecloud.keycloak',
            'social_django'
        ), SOCIAL_AUTH_KEYCLOAK_KEY='key', SOCIAL_AUTH_KEYCLOAK_SECRET='secret'))
    @patch('wirecloud.keycloak.utils.build_backend', new=MagicMock())
    @patch('wirecloud.keycloak.utils.build_version_hash', new=MagicMock())
    @patch('wirecloud.keycloak.utils.load_strategy', new=MagicMock())
    def test_proxy_workspace_owner_token_not_filtered(self):
        oauth_info = MagicMock(access_token='token')
        oauth_info.access_token_expired.return_value = True

        user = MagicMock()
        user.social_auth.get.return_value = oauth_info

        workspace = MagicMock(creator=user)
        request = {
            'url': 'http://proxy.com/url/?id=1',
            'headers': {
                'fiware-oauth-token': 'token1',
                'fiware-oauth-header-name': 'Authorization',
                'fiware-oauth-source': 'workspaceowner',
                'fiware-oauth-get-parameter': 'x-api-key'
            },
            'workspace': workspace
        }

        self._text_proxy_processor(request)

        # Validate oauth info calls
        user.social_auth.get.assert_called_once_with(provider='keycloak')
        oauth_info.access_token_expired.assert_called_once_with()
        oauth_info.refresh_token.assert_called_once_with(self._strategy)

        self.assertEqual({
            'Authorization': 'Bearer token'
        }, request['headers'])
        self.assertEqual('http://proxy.com/url/?id=1&x-api-key=token', request['url'])


if __name__ == "__main__":
    unittest.main(verbosity=2)
