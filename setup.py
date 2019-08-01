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

import os
import setuptools

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setuptools.setup(
    name='wirecloud-keycloak',
    version='0.1.1',
    author="FICODES",
    author_email="contact@ficodes.com",
    description="WireCloud extension supporting authentication with Keycloak IDM",
    long_description=read('./README.md'),
    long_description_content_type="text/markdown",
    url="https://github.com/Ficodes/wirecloud-keycloak",
    packages=setuptools.find_packages(),
    license="AGPLv3+",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    install_requires=(
        "wirecloud>=1.2.0",
        "pyJwt>=1.7.1",
        "cryptography>=2.6.1"
    )
)