// Copyright (c) 2020 Famedly GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

/// This exception is thrown on Native only. olm.js does not detect
/// use-after-free, resulting in undefined behavior on Web.
class UseAfterFreeError extends Error {
  String toString() =>
      'Attempted to use (or double-free) a freed libolm object';
}
