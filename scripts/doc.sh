#!/bin/sh -e
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
dart doc --exclude dart:async,dart:collection,dart:convert,dart:core,dart:developer,dart:io,dart:isolate,dart:math,dart:typed_data,dart:ui
sed -i '/https:\/\/famedly.gitlab.io\/libraries\/dart-olm\/#architecture/!b;g;r doc/architecture.inc' doc/api/index.html
