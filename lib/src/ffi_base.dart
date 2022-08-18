// Copyright (c) 2020 Famedly GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

final libolm = Platform.isIOS
    ? DynamicLibrary.process()
    : DynamicLibrary.open(Platform.isAndroid
        ? 'libolm.so'
        : Platform.isWindows
            ? 'libolm.dll'
            : Platform.isMacOS
                ? 'libolm.3.dylib'
                : 'libolm.so.3');

void throw_olm(Pointer<Utf8> message) {
  throw Exception(message.toDartString());
}
