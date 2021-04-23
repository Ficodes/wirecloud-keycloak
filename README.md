# WireCloud Keycloak plugin

[![Tests](https://github.com/Ficodes/wirecloud-keycloak/actions/workflows/tests.yml/badge.svg)](https://github.com/Ficodes/wirecloud-keycloak/actions/workflows/tests.yml)
[![Coverage Status](https://coveralls.io/repos/github/Ficodes/wirecloud-keycloak/badge.svg?branch=master)](https://coveralls.io/github/Ficodes/wirecloud-keycloak?branch=master)

This WireCloud plugin allows the usage of Keycloak as IDM for the authentication of WireCloud
users as well as the usage of JWT tokens issued for those users to access to backend services.

This plugin can be installed with pip as follows:

```
pip install wirecloud-keycloak
```

Or using the sources:

```
python setup.py install
```

Once installed, it can be enabled by editing your `settings.py` file and including `wirecloud.keycloak` and `social_django` on the `INSTALLED_APPS` setting, addiding `KeycloakOpenIdConnect` as the authentication backend to use and configuring it.

```
INSTALLED_APPS += (
    # 'django.contrib.sites',
    # 'wirecloud.oauth2provider',
    'wirecloud.keycloak',
    'haystack',
    'social_django'
)

AUTHENTICATION_BACKENDS = ('wirecloud.keycloak.social_auth_backend.KeycloakOpenIdConnect',)

SOCIAL_AUTH_NO_DEFAULT_PROTECTED_USER_FIELDS = True
SOCIAL_AUTH_PROTECTED_USER_FIELDS = ('username', 'id', 'pk', 'email', 'password', 'is_active')

SOCIAL_AUTH_KEYCLOAK_OIDC_URL = 'https://keycloak.example.com'
SOCIAL_AUTH_KEYCLOAK_OIDC_REALM = 'demo'
SOCIAL_AUTH_KEYCLOAK_OIDC_KEY = 'wirecloud'
SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET = '7667d30b-4e1a-4dfe-a040-0b6fdc4758f5'
SOCIAL_AUTH_KEYCLOAK_OIDC_GLOBAL_ROLE = True
```

These settings include:

* `SOCIAL_AUTH_KEYCLOAK_OIDC_URL`: URL of the Keycloak server
* `SOCIAL_AUTH_KEYCLOAK_OIDC_REALM`: Keycloak realm where WireCloud is registered
* `SOCIAL_AUTH_KEYCLOAK_OIDC_KEY`: Client ID of the WireCloud application
* `SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET`: Client secret of the WireCloud application
* `SOCIAL_AUTH_KEYCLOAK_OIDC_GLOBAL_ROLE`: Whether the admin role is taken from the realm instead of from the client (default: `False`)

This plugin is able to map Keycloak roles into WireCloud groups. To enable it, you should enable the `realm roles` and the `client roles` mappings either for the wirecloud application or for the `roles` scope. This mapping should include role information on the ID token.

Finally, to add backchannel logout support (Single Sign Off), the following code: `url('', include('wirecloud.keycloak.urls')),` has to be added inside the urlpatterns list defined on your `urls.py` file. Once done this, you can access the Keycloak console to configure the **Admin URL** of the WireCloud application to point into the following url: `http(s)://wirecloud.example.com/keycloak`.
