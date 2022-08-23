#!/bin/sh -e
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
mkdir js
# download olm 3.2.12 package: https://gitlab.matrix.org/matrix-org/olm/-/packages/89
curl -L "https://gitlab.matrix.org/matrix-org/olm/-/package_files/374/download" | tar xz -C js
