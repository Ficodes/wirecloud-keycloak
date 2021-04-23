# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 Future Internet Consulting and Development Solutions S.L.

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

from django.conf import settings
from django.conf.urls import url
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import cache_page

from wirecloud.keycloak.utils import build_version_hash, build_backend, get_social_auth_model
from wirecloud.platform.plugins import WirecloudPlugin

get_version_hash = build_version_hash()

try:
    KEYCLOAK_SOCIAL_AUTH_BACKEND = build_backend()

    IDM_SUPPORT_ENABLED = 'wirecloud.keycloak' in settings.INSTALLED_APPS and 'social_django' in settings.INSTALLED_APPS \
        and getattr(settings, 'SOCIAL_AUTH_KEYCLOAK_OIDC_KEY', None) is not None and getattr(settings, 'SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET', None) is not None

except Exception:
    IDM_SUPPORT_ENABLED = False


def auth_keycloak_token(auth_type, token):

    UserSocialAuth = get_social_auth_model()
    user_data = KEYCLOAK_SOCIAL_AUTH_BACKEND.user_data(token)
    return UserSocialAuth.objects.get(provider='keycloak_oidc', uid=user_data['username']).user


class KeycloakPlugin(WirecloudPlugin):
    def get_urls(self):

        if IDM_SUPPORT_ENABLED:
            from wirecloud.keycloak.views import oauth_discovery
            return (
                url('^.well-known/oauth$', cache_page(7 * 24 * 60 * 60, key_prefix='well-known-oauth-%s' % get_version_hash())(oauth_discovery), name='oauth.discovery'),
            )
        else:
            return ()

    def get_api_auth_backends(self):

        if IDM_SUPPORT_ENABLED:
            return {
                'Bearer': auth_keycloak_token,
            }
        else:
            return {}

    def get_constants(self):
        constants = {}

        if IDM_SUPPORT_ENABLED:
            global KEYCLOAK_SOCIAL_AUTH_BACKEND
            constants["KEYCLOAK_URL"] = KEYCLOAK_SOCIAL_AUTH_BACKEND.URL

        return constants

    def get_proxy_processors(self):
        if not IDM_SUPPORT_ENABLED:
            return ()

        return ('wirecloud.keycloak.proxy.IDMTokenProcessor',)

    def get_platform_context_definitions(self):
        # Using default FIWARE token parameter for compatibility with existing widgets
        return {
            'fiware_token_available': {
                'label': _('FIWARE token available'),
                'description': _('Indicates if the current user has associated a FIWARE auth token that can be used for accessing other FIWARE resources'),
            },
        }

    def get_platform_context_current_values(self, user, **kwargs):
        # Work around bug when running manage.py compress
        if not IDM_SUPPORT_ENABLED:
            fiware_token_available = False
        elif callable(user.is_authenticated):
            fiware_token_available = user.is_authenticated() and user.social_auth.filter(provider='keycloak_oidc').exists()
        else:
            fiware_token_available = user.is_authenticated and user.social_auth.filter(provider='keycloak_oidc').exists()
        return {
            'fiware_token_available': fiware_token_available
        }

    def get_django_template_context_processors(self):
        context = {}

        if IDM_SUPPORT_ENABLED:
            context["KEYCLOAK_URL"] = getattr(settings, "SOCIAL_AUTH_KEYCLOAK_OIDC_URL", '')
            # We don't support using different URLs for internal and public use
            context["KEYCLOAK_PUBLIC_URL"] = context["KEYCLOAK_URL"]
        else:
            context["KEYCLOAK_URL"] = None
            context["KEYCLOAK_PUBLIC_URL"] = None

        # Using FIWARE context variables for compatibility with existing template
        context["FIWARE_IDM_SERVER"] = context["KEYCLOAK_URL"]
        context["FIWARE_IDM_PUBLIC_URL"] = context["KEYCLOAK_PUBLIC_URL"]

        return context
