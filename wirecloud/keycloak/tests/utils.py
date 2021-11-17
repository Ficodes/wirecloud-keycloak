# -*- coding: utf-8 -*-

# Copyright (c) 2021 Future Internet Consulting and Development Solutions S.L.

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

import sys

import unittest
from unittest import TestCase
from unittest.mock import patch, MagicMock

from wirecloud.keycloak.utils import build_backend


class KeycloakUtilsTestCase(TestCase):

    @patch.dict("sys.modules", new=[])
    def test_build_backend_social_auth_4(self):
        social_django = MagicMock()
        sys.modules["social_django"] = social_django
        sys.modules["social_django.utils"] = social_django.utils

        build_backend()

    @patch.dict("sys.modules", new=[])
    def test_build_backend_social_auth_5(self):
        social_django = MagicMock()
        sys.modules["social_django"] = social_django
        sys.modules["social_django.utils"] = social_django.utils
        del social_django.utils.BACKENDS

        build_backend()


if __name__ == "__main__":
    unittest.main(verbosity=2)
