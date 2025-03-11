#!/bin/sh
# Copyright (c) 2020 Famedly GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later

cd "$(dirname "$0")"/..
./scripts/prepare_js.sh
./scripts/prepare_native.sh
dart pub get
dart run ffigen
sed -i '1i import '\''package:ffi/ffi.dart'\'';\nimport '\''package:olm/src/ffi_base.dart'\'';' lib/src/ffigen.dart
# just use nativetype instead of opaque, same thing afaik
sed -i 's/\(OlmInboundGroupSession\|OlmOutboundGroupSession\|OlmAccount\|OlmSession\|OlmUtility\|OlmSAS\|OlmPkEncryption\|OlmPkDecryption\|OlmPkSigning\)/ffi.NativeType/g' lib/src/ffigen.dart
sed -i '/final class ffi.NativeType extends ffi.Opaque {}/d' lib/src/ffigen.dart
# because we can't work nicely with generic pointers
sed -i 's/ffi.Pointer<ffi.Void>/ffi.Pointer<ffi.Uint8>/g' lib/src/ffigen.dart
sed -i 's/ffi.Pointer<ffi.Char>/ffi.Pointer<Utf8>/g' lib/src/ffigen.dart
python3 ./scripts/error_handling.py
dart format .
dart run import_sorter:main --no-comments