#!/bin/sh -e
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
dart doc
sed -i '/https:\/\/famedly.gitlab.io\/libraries\/dart-olm\/#architecture/!b;g;r doc/architecture.inc' doc/api/index.html
