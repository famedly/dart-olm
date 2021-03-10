#!/bin/sh -e
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
[ -d native/olm ] && export LD_LIBRARY_PATH=$(pwd)/native/olm
pub run test -p vm,firefox --coverage coverage
pub run coverage:format_coverage --packages .packages --report-on lib/ -l -o coverage/lcov.info -i coverage
genhtml -o coverage coverage/lcov.info || scripts/lcov_stats.sh coverage/lcov.info || true

mkdir -p build
dart2native test/olm_test.dart -o build/olm_test.exe
valgrind --show-mismatched-frees=no --exit-on-first-error=yes --error-exitcode=1 build/olm_test.exe
