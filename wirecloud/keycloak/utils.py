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


def build_version_hash():
    from wirecloud.platform.core.plugins import get_version_hash
    return get_version_hash


def build_backend():
    from social_django.utils import BACKENDS, get_backend,  load_strategy
    return get_backend(BACKENDS, 'keycloak')(load_strategy())


def build_simple_backend():
    from social_django.utils import BACKENDS, get_backend
    return get_backend(BACKENDS, 'keycloak')


def load_strategy():
    from social_django.utils import load_strategy
    return load_strategy()


def get_social_auth_model():
    from social_django.models import UserSocialAuth
    return UserSocialAuth
