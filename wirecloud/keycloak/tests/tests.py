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

from wirecloud.keycloak.tests.social_backend import KeycloakSocialAuthBackendTestCase
from wirecloud.keycloak.tests.plugins import KeycloakPluginTestCase
from wirecloud.keycloak.tests.proxy import IDMTokenProcessorTestCase
from wirecloud.keycloak.tests.views import KeycloakViewTestCase


if __name__ == "__main__":
    unittest.main(verbosity=2)
