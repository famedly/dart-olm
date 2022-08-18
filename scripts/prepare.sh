#!/bin/sh
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
./scripts/prepare_js.sh
./scripts/prepare_native.sh
dart pub get
