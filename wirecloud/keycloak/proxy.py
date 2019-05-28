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

from io import BytesIO
import time

from django.conf import settings
from django.utils.http import urlquote_plus
from django.utils.translation import ugettext as _

from wirecloud.fiware import FIWARE_LAB_CLOUD_SERVER
from wirecloud.fiware.openstack_token_manager import OpenstackTokenManager
from wirecloud.fiware.plugins import IDM_SUPPORT_ENABLED
from wirecloud.proxy.utils import ValidationError


if IDM_SUPPORT_ENABLED:
    from social_django.utils import load_strategy
    STRATEGY = load_strategy()
else:
    STRATEGY = None


class IDMTokenProcessor(object):
    pass
