# WireCloud Keycloak plugin

This WireCloud plugin allows the usage of Keycloak as IDM for the authentication of WireCloud
users as well as the usage of JWT tokens issued for those users to access to backend services.

This plugin can be installed with pip as follows:

```
pip install wirecloud-keycloak
```

Or using the sources:

```
python setup.py develop
```

Once installed, it can be enabled by including *wirecloud.keycloak* and *social_django*
in INSTALLED_APPS setting, and addiding *KeycloakOAuth2* as an authentication backend.

```
INSTALLED_APPS += (
    # 'django.contrib.sites',
    # 'wirecloud.oauth2provider',
    'wirecloud.keycloak',
    'haystack',
    'social_django'
)

AUTHENTICATION_BACKENDS = ('wirecloud.keycloak.social_auth_backend.KeycloakOAuth2',)
```

Finally the following settings need to be included in *setting.py* file.

```
KEYCLOAK_IDM_SERVER = 'http://keycloak.docker:8080'
KEYCLOAK_REALM = 'demo'
KEYCLOAK_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkY9D3w8J/NPtD2DT/fvPwvrU0WBtw7F6mDTV8JG3TjsrQF4HCEjExDYN9M+5GeJTu8WNfDFUzEfuq7OS/3FRLgZJnV0naYlQsH50l5vCzMD2p9vSSECHBDuz/woObHujgtQckPDv7wyWjihn4EJthI4K08Fb06quijux0M+mazF5WDqlOy3UuKlfERv8JskpOBjwnhCMwz5zv/ox8Y++AiBXlL4stqok29AXANt29+A8LvYDNXiSYuHZJeAk3oxI7G8PYQHFOTynR41hm8xNxPf8YSx2nS7ZfHBPtt9rz7QdPZ9LmXwKPpo+ml92YfHSPcmW2beOuILJ1DW8ZO5eZQIDAQAB'

SOCIAL_AUTH_KEYCLOAK_KEY = 'wirecloud'
SOCIAL_AUTH_KEYCLOAK_SECRET = '7667d30b-4e1a-4dfe-a040-0b6fdc4758f5'

```

These settings include:
* **KEYCLOAK_IDM_SERVER**: URL of the Keycloak instance
* **KEYCLOAK_REALM**: Keycloak realm where WireCloud is registered
* **KEYCLOAK_KEY**: RSA Key used to decode JWT
* **SOCIAL_AUTH_KEYCLOAK_KEY**: Client ID of the WireCloud application
* **SOCIAL_AUTH_KEYCLOAK_SECRET**: Client secret of the WireCloud application
