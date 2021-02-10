// Copyright (c) 2020 Famedly GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'src/ffi.dart';
import 'dart:convert';
import 'dart:ffi';
import 'dart:math';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:ffi/ffi.dart' as ffi;

typedef _ObjectLengthFunc = int Function(Pointer<NativeType>);
typedef _PickleUnpickleFunc = int Function(Pointer<NativeType>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _CalculateMacFunc = int Function(Pointer<NativeType>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

String _readStr(_ObjectLengthFunc len, int Function(Pointer<NativeType>, Pointer<Uint8>, int) data, Pointer<NativeType> inst) {
  final l = len(inst);
  final mem = allocate<Uint8>(count: l);
  try {
    data(inst, mem, l);
    return utf8.decode(mem.asTypedList(l));
  } finally {
    free(mem);
  }
}

String _pickle(_ObjectLengthFunc len, _PickleUnpickleFunc data, Pointer<NativeType> inst, String key) {
  final units = utf8.encode(key);
  final outLen = len(inst);
  final mem = allocate<Uint8>(count: units.length + outLen);
  final outMem = mem.elementAt(units.length);
  try {
    mem.asTypedList(units.length).setAll(0, units);
    data(inst, mem, units.length, outMem, outLen);
    return utf8.decode(outMem.asTypedList(outLen));
  } finally {
    free(mem);
  }
}

void _unpickle(_PickleUnpickleFunc func, Pointer<NativeType> inst, String data, String key) {
  final dby = utf8.encode(data);
  final kby = utf8.encode(key);
  final mem = allocate<Uint8>(count: dby.length + kby.length);
  final keyMem = mem.elementAt(dby.length);
  try {
    mem.asTypedList(dby.length).setAll(0, dby);
    keyMem.asTypedList(kby.length).setAll(0, kby);
    func(inst, keyMem, kby.length, mem, dby.length);
  } finally {
    free(mem);
  }
}

String _calculateMac(_CalculateMacFunc func, Pointer<NativeType> inst, String input, String info) {
  final inputUnits = utf8.encode(input);
  final infoUnits = utf8.encode(info);
  final outMemLen = olm_sas_mac_length(inst);
  final mem = allocate<Uint8>(count: inputUnits.length + infoUnits.length + outMemLen);
  final infoMem = mem.elementAt(inputUnits.length);
  final outMem = infoMem.elementAt(infoUnits.length);
  try {
    mem.asTypedList(inputUnits.length).setAll(0, inputUnits);
    infoMem.asTypedList(infoUnits.length).setAll(0, infoUnits);
    func(inst, mem, inputUnits.length, infoMem, infoUnits.length, outMem, outMemLen);
    return utf8.decode(outMem.asTypedList(outMemLen));
  } finally {
    ffi.free(mem);
  }
}

void _fillRandom(Uint8List list) {
  final rng = Random.secure();
  list.setAll(0, Iterable.generate(list.length, (i) => rng.nextInt(256)));
}

void _createRandom(void Function(Pointer<NativeType>, Pointer<Uint8> random, int size) func, _ObjectLengthFunc len, Pointer<NativeType> inst) {
  final l = len(inst);
  final mem = allocate<Uint8>(count: l);
  try {
    _fillRandom(mem.asTypedList(l));
    func(inst, mem, l);
  } finally {
    free(mem);
  }
}

Future<void> init() async {
  olm_get_library_version; // just load the function, not calling it
}

List<int> get_library_version() {
  final mem = allocate<Uint8>(count: 3);
  try {
    olm_get_library_version(mem.elementAt(0), mem.elementAt(1), mem.elementAt(2));
    return List<int>.from(mem.asTypedList(3));
  } finally {
    free(mem);
  }
}

class EncryptResult {
  int type;
  String body;
  EncryptResult._(this.type, this.body);
}

class DecryptResult {
  int message_index;
  String plaintext;
  DecryptResult._(this.message_index, this.plaintext);
}

class Account {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  Account() {
    _mem = allocate<Uint8>(count: olm_account_size());
    _inst = olm_account(_mem);
  }

  void free() {
    olm_clear_account(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  void create() {
    _createRandom(olm_create_account, olm_create_account_random_length, _inst);
  }

  String identity_keys() {
    return _readStr(olm_account_identity_keys_length, olm_account_identity_keys, _inst);
  }

  String one_time_keys() {
    return _readStr(olm_account_one_time_keys_length, olm_account_one_time_keys, _inst);
  }

  String pickle(String key) {
    return _pickle(olm_pickle_account_length, olm_pickle_account, _inst, key);
  }

  void unpickle(String key, String data) {
    return _unpickle(olm_unpickle_account, _inst, data, key);
  }

  void generate_one_time_keys(int count) {
    _createRandom((inst, random, size) => olm_account_generate_one_time_keys(_inst, count, random, size), (inst) => olm_account_generate_one_time_keys_random_length(inst, count), _inst);
  }

  void remove_one_time_keys(Session session) {
    olm_remove_one_time_keys(_inst, session._inst);
  }

  void mark_keys_as_published() {
    olm_account_mark_keys_as_published(_inst);
  }

  int max_number_of_one_time_keys() {
    return olm_account_max_number_of_one_time_keys(_inst);
  }

  String sign(String message) {
    final units = utf8.encode(message);
    final outLen = olm_account_signature_length(_inst);
    final mem = allocate<Uint8>(count: units.length + outLen);
    final outMem = mem.elementAt(units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_account_sign(_inst, mem, units.length, outMem, outLen);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }
}

class Session {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  Session() {
    _mem = allocate<Uint8>(count: olm_session_size());
    _inst = olm_session(_mem);
  }

  void free() {
    olm_clear_session(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String pickle(String key) {
    return _pickle(olm_pickle_session_length, olm_pickle_session, _inst, key);
  }

  void unpickle(String key, String data) {
    return _unpickle(olm_unpickle_session, _inst, data, key);
  }

  void create_outbound(Account account, String identity_key, String one_time_key) {
    final identity_key_units = utf8.encode(identity_key);
    final one_time_key_units = utf8.encode(one_time_key);
    final randomLen = olm_create_outbound_session_random_length(_inst);
    final mem = allocate<Uint8>(count: identity_key_units.length + one_time_key_units.length + randomLen);
    final otMem = mem.elementAt(identity_key_units.length);
    final rndMem = otMem.elementAt(one_time_key_units.length);
    try {
      mem.asTypedList(identity_key_units.length).setAll(0, identity_key_units);
      otMem.asTypedList(one_time_key_units.length).setAll(0, one_time_key_units);
      _fillRandom(rndMem.asTypedList(randomLen));
      olm_create_outbound_session(_inst, account._inst, mem, identity_key_units.length, otMem, one_time_key_units.length, rndMem, randomLen);
    } finally {
      ffi.free(mem);
    }
  }

  void create_inbound(Account account, String message) {
    final message_units = utf8.encode(message);
    final mem = allocate<Uint8>(count: message_units.length);
    try {
      mem.asTypedList(message_units.length).setAll(0, message_units);
      olm_create_inbound_session(_inst, account._inst, mem, message_units.length);
    } finally {
      ffi.free(mem);
    }
  }

  void create_inbound_from(Account account, String identity_key, String one_time_key) {
    final identity_key_units = utf8.encode(identity_key);
    final one_time_key_units = utf8.encode(one_time_key);
    final mem = allocate<Uint8>(count: identity_key_units.length + one_time_key_units.length);
    final otMem = mem.elementAt(identity_key_units.length);
    try {
      mem.asTypedList(identity_key_units.length).setAll(0, identity_key_units);
      otMem.asTypedList(one_time_key_units.length).setAll(0, one_time_key_units);
      olm_create_inbound_session_from(_inst, account._inst, mem, identity_key_units.length, otMem, one_time_key_units.length);
    } finally {
      ffi.free(mem);
    }
  }

  String session_id() {
    return _readStr(olm_session_id_length, olm_session_id, _inst);
  }

  bool has_received_message() {
    return olm_session_has_received_message(_inst) != 0;
  }

  int encrypt_message_type() {
    return olm_encrypt_message_type(_inst);
  }

  bool matches_inbound(String message) {
    final message_units = utf8.encode(message);
    final mem = allocate<Uint8>(count: message_units.length);
    mem.asTypedList(message_units.length).setAll(0, message_units);
    try {
      return olm_matches_inbound_session(_inst, mem, message_units.length) != 0;
    } finally {
      ffi.free(mem);
    }
  }

  bool matches_inbound_from(String identity_key, String message) {
    final identity_key_units = utf8.encode(identity_key);
    final message_units = utf8.encode(message);
    final mem = allocate<Uint8>(count: identity_key_units.length + message_units.length);
    final mem2 = mem.elementAt(identity_key_units.length);
    mem.asTypedList(identity_key_units.length).setAll(0, identity_key_units);
    mem2.asTypedList(message_units.length).setAll(0, message_units);
    try {
      return olm_matches_inbound_session_from(_inst, mem, identity_key_units.length, mem2, message_units.length) != 0;
    } finally {
      ffi.free(mem);
    }
  }

  EncryptResult encrypt(String plaintext) {
    final units = utf8.encode(plaintext);
    final randomLen = olm_encrypt_random_length(_inst);
    final outLen = olm_encrypt_message_length(_inst, units.length);
    final mem = allocate<Uint8>(count: units.length + randomLen + outLen);
    final rndMem = mem.elementAt(units.length);
    final outMem = rndMem.elementAt(randomLen);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      _fillRandom(rndMem.asTypedList(randomLen));
      final result1 = encrypt_message_type();
      olm_encrypt(_inst, mem, units.length, rndMem, randomLen, outMem, outLen);
      final result2 = utf8.decode(outMem.asTypedList(outLen));
      return EncryptResult._(result1, result2);
    } finally {
      ffi.free(mem);
    }
  }

  String decrypt(int message_type, String message) {
    final units = utf8.encode(message);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      int outLen = olm_decrypt_max_plaintext_length(_inst, message_type, mem, units.length);
      mem.asTypedList(units.length).setAll(0, units);
      final outMem = allocate<Uint8>(count: outLen);
      try {
        outLen = olm_decrypt(_inst, message_type, mem, units.length, outMem, outLen);
        return utf8.decode(outMem.asTypedList(outLen));
      } finally {
        ffi.free(outMem);
      }
    } finally {
      ffi.free(mem);
    }
  }
}

class Utility {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  Utility() {
    _mem = allocate<Uint8>(count: olm_utility_size());
    _inst = olm_utility(_mem);
  }

  void free() {
    olm_clear_utility(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String sha256(String input) {
    return sha256_bytes(utf8.encoder.convert(input));
  }

  /// Not implemented for Web in upstream olm.
  String sha256_bytes(Uint8List input) {
    final mem = allocate<Uint8>(count: input.length);
    mem.asTypedList(input.length).setAll(0, input);
    try {
      return sha256_pointer(mem, input.length);
    } finally {
      ffi.free(mem);
    }
  }

  /// Available for Native only.
  String sha256_pointer(Pointer<Uint8> input, int size) {
    final outLen = olm_sha256_length(_inst);
    final outMem = allocate<Uint8>(count: outLen);
    try {
      olm_sha256(_inst, input, size, outMem, outLen);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(outMem);
    }
  }

  void ed25519_verify(String key, String message, String signature) {
    final key_units = utf8.encode(key);
    final message_units = utf8.encode(message);
    final signature_units = utf8.encode(signature);
    final mem1 = allocate<Uint8>(count: key_units.length + message_units.length + signature_units.length);
    final mem2 = mem1.elementAt(key_units.length);
    final mem3 = mem2.elementAt(message_units.length);
    try {
      mem1.asTypedList(key_units.length).setAll(0, key_units);
      mem2.asTypedList(message_units.length).setAll(0, message_units);
      mem3.asTypedList(signature_units.length).setAll(0, signature_units);
      olm_ed25519_verify(_inst, mem1, key_units.length, mem2, message_units.length, mem3, signature_units.length);
    } finally {
      ffi.free(mem1);
    }
  }
}

class InboundGroupSession {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  InboundGroupSession() {
    _mem = allocate<Uint8>(count: olm_inbound_group_session_size());
    _inst = olm_inbound_group_session(_mem);
  }

  void free() {
    olm_clear_inbound_group_session(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String pickle(String key) {
    return _pickle(olm_pickle_inbound_group_session_length, olm_pickle_inbound_group_session, _inst, key);
  }

  void unpickle(String key, String data) {
    return _unpickle(olm_unpickle_inbound_group_session, _inst, data, key);
  }

  void create(String session_key) {
    final units = utf8.encode(session_key);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_init_inbound_group_session(_inst, mem, units.length);
    } finally {
      ffi.free(mem);
    }
  }

  void import_session(String session_key) {
    final units = utf8.encode(session_key);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_import_inbound_group_session(_inst, mem, units.length);
    } finally {
      ffi.free(mem);
    }
  }

  DecryptResult decrypt(String message) {
    final units = utf8.encode(message);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      int outLen = olm_group_decrypt_max_plaintext_length(_inst, mem, units.length);
      mem.asTypedList(units.length).setAll(0, units);
      final outMem = allocate<Uint8>(count: outLen + 4);
      final outMem2 = outMem.elementAt(outLen).cast<Uint32>();
      try {
        outLen = olm_group_decrypt(_inst, mem, units.length, outMem, outLen, outMem2);
        return DecryptResult._(outMem2.value, utf8.decode(outMem.asTypedList(outLen)));
      } finally {
        ffi.free(outMem);
      }
    } finally {
      ffi.free(mem);
    }
  }

  String session_id() {
    return _readStr(olm_inbound_group_session_id_length, olm_inbound_group_session_id, _inst);
  }

  int first_known_index() {
    return olm_inbound_group_session_first_known_index(_inst);
  }

  String export_session(int message_index) {
    return _readStr(olm_export_inbound_group_session_length, (inst, mem, len) => olm_export_inbound_group_session(inst, mem, len, message_index), _inst);
  }
}

class OutboundGroupSession {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  OutboundGroupSession() {
    _mem = allocate<Uint8>(count: olm_outbound_group_session_size());
    _inst = olm_outbound_group_session(_mem);
  }

  void free() {
    olm_clear_outbound_group_session(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String pickle(String key) {
    return _pickle(olm_pickle_outbound_group_session_length, olm_pickle_outbound_group_session, _inst, key);
  }

  void unpickle(String key, String data) {
    return _unpickle(olm_unpickle_outbound_group_session, _inst, data, key);
  }

  void create() {
    _createRandom(olm_init_outbound_group_session, olm_init_outbound_group_session_random_length, _inst);
  }

  String encrypt(String plaintext) {
    final units = utf8.encode(plaintext);
    final outLen = olm_group_encrypt_message_length(_inst, units.length);
    final mem = allocate<Uint8>(count: units.length + outLen);
    final outMem = mem.elementAt(units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_group_encrypt(_inst, mem, units.length, outMem, outLen);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }

  String session_id() {
    return _readStr(olm_outbound_group_session_id_length, olm_outbound_group_session_id, _inst);
  }

  int message_index() {
    return olm_outbound_group_session_message_index(_inst);
  }

  String session_key() {
    return _readStr(olm_outbound_group_session_key_length, olm_outbound_group_session_key, _inst);
  }
}

class SAS {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  SAS() {
    _mem = allocate<Uint8>(count: olm_sas_size());
    _inst = olm_sas(_mem);
    _createRandom(olm_create_sas, olm_create_sas_random_length, _inst);
  }

  void free() {
    olm_clear_sas(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String get_pubkey() {
    return _readStr(olm_sas_pubkey_length, olm_sas_get_pubkey, _inst);
  }

  void set_their_key(String their_key) {
    final units = utf8.encode(their_key);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_sas_set_their_key(_inst, mem, units.length);
    } finally {
      ffi.free(mem);
    }
  }

  Uint8List generate_bytes(String info, int length) {
    final units = utf8.encode(info);
    final mem = allocate<Uint8>(count: units.length + length);
    final outMem = mem.elementAt(units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_sas_generate_bytes(_inst, mem, units.length, outMem, length);
      return Uint8List.fromList(outMem.asTypedList(length));
    } finally {
      ffi.free(mem);
    }
  }

  String calculate_mac(String input, String info) {
    return _calculateMac(olm_sas_calculate_mac, _inst, input, info);
  }

  String calculate_mac_long_kdf(String input, String info) {
    return _calculateMac(olm_sas_calculate_mac_long_kdf, _inst, input, info);
  }
}

class PkEncryptResult {
  String ciphertext;
  String mac;
  String ephemeral;
  PkEncryptResult._(this.ciphertext, this.mac, this.ephemeral);
}

class PkEncryption {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  PkEncryption() {
    _mem = allocate<Uint8>(count: olm_pk_encryption_size());
    _inst = olm_pk_encryption(_mem);
  }

  void free() {
    olm_clear_pk_encryption(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  void set_recipient_key(String key) {
    final units = utf8.encode(key);
    final mem = allocate<Uint8>(count: units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_pk_encryption_set_recipient_key(_inst, mem, units.length);
    } finally {
      ffi.free(mem);
    }
  }

  PkEncryptResult encrypt(String plaintext) {
    final units = utf8.encode(plaintext);
    final rndLen = olm_pk_encrypt_random_length(_inst);
    final outLen = olm_pk_ciphertext_length(_inst, units.length);
    final macLen = olm_pk_mac_length(_inst);
    final ephLen = olm_pk_key_length();
    final mem = allocate<Uint8>(count: units.length + rndLen + outLen + macLen + ephLen);
    final rndMem = mem.elementAt(units.length);
    final outMem = rndMem.elementAt(rndLen);
    final macMem = outMem.elementAt(outLen);
    final ephMem = macMem.elementAt(macLen);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      _fillRandom(rndMem.asTypedList(rndLen));
      olm_pk_encrypt(_inst, mem, units.length, outMem, outLen, macMem, macLen, ephMem, ephLen, rndMem, rndLen);
      return PkEncryptResult._(
        utf8.decode(outMem.asTypedList(outLen)),
        utf8.decode(macMem.asTypedList(macLen)),
        utf8.decode(ephMem.asTypedList(ephLen))
      );
    } finally {
      ffi.free(mem);
    }
  }
}

class PkDecryption {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  PkDecryption() {
    _mem = allocate<Uint8>(count: olm_pk_decryption_size());
    _inst = olm_pk_decryption(_mem);
  }

  void free() {
    olm_clear_pk_decryption(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String init_with_private_key(Uint8List private_key) {
    final outLen = olm_pk_key_length();
    final mem = allocate<Uint8>(count: private_key.length + outLen);
    final outMem = mem.elementAt(private_key.length);
    try {
      mem.asTypedList(private_key.length).setAll(0, private_key);
      olm_pk_key_from_private(_inst, outMem, outLen, mem, private_key.length);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }

  String generate_key() {
    final len = olm_pk_private_key_length();
    final outLen = olm_pk_key_length();
    final mem = allocate<Uint8>(count: len + outLen);
    final outMem = mem.elementAt(len);
    try {
      _fillRandom(mem.asTypedList(len));
      olm_pk_key_from_private(_inst, outMem, outLen, mem, len);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }

  Uint8List get_private_key() {
    final len = olm_pk_private_key_length();
    final mem = allocate<Uint8>(count: len);
    try {
      olm_pk_get_private_key(_inst, mem, len);
      return Uint8List.fromList(mem.asTypedList(len));
    } finally {
      ffi.free(mem);
    }
  }

  String pickle(String key) {
    return _pickle(olm_pickle_pk_decryption_length, olm_pickle_pk_decryption, _inst, key);
  }

  String unpickle(String key, String data) {
    final dby = utf8.encode(data);
    final kby = utf8.encode(key);
    final outLen = olm_pk_key_length();
    final mem = allocate<Uint8>(count: dby.length + kby.length + outLen);
    final keyMem = mem.elementAt(dby.length);
    final outMem = keyMem.elementAt(kby.length);
    try {
      mem.asTypedList(dby.length).setAll(0, dby);
      keyMem.asTypedList(kby.length).setAll(0, kby);
      olm_unpickle_pk_decryption(_inst, keyMem, kby.length, mem, dby.length, outMem, outLen);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }

  String decrypt(String ephemeral_key, String mac, String ciphertext) {
    final ephUnits = utf8.encode(ephemeral_key);
    final macUnits = utf8.encode(mac);
    final ciphertextUnits = utf8.encode(ciphertext);

    int plaintextLen = olm_pk_max_plaintext_length(_inst, ciphertextUnits.length);
    final mem = allocate<Uint8>(count: ephUnits.length + macUnits.length + ciphertextUnits.length + plaintextLen);
    final macMem = mem.elementAt(ephUnits.length);
    final ciphertextMem = macMem.elementAt(macUnits.length);
    final plaintextMem = ciphertextMem.elementAt(ciphertextUnits.length);
    try {
      mem.asTypedList(ephUnits.length).setAll(0, ephUnits);
      macMem.asTypedList(macUnits.length).setAll(0, macUnits);
      ciphertextMem.asTypedList(ciphertextUnits.length).setAll(0, ciphertextUnits);
      plaintextLen = olm_pk_decrypt(_inst, mem, ephUnits.length, macMem, macUnits.length, ciphertextMem, ciphertextUnits.length, plaintextMem, plaintextLen);
      return utf8.decode(plaintextMem.asTypedList(plaintextLen));
    } finally {
      ffi.free(mem);
    }
  }
}

class PkSigning {
  Pointer<Uint8> _mem;
  Pointer<NativeType> _inst;

  PkSigning() {
    _mem = allocate<Uint8>(count: olm_pk_signing_size());
    _inst = olm_pk_signing(_mem);
  }

  void free() {
    olm_clear_pk_signing(_inst);
    _inst = null;
    ffi.free(_mem);
  }

  String init_with_seed(Uint8List seed) {
    final outLen = olm_pk_signing_public_key_length();
    final mem = allocate<Uint8>(count: seed.length + outLen);
    final outMem = mem.elementAt(seed.length);
    try {
      mem.asTypedList(seed.length).setAll(0, seed);
      olm_pk_signing_key_from_seed(_inst, outMem, outLen, mem, seed.length);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }

  Uint8List generate_seed() {
    final result = Uint8List(olm_pk_signing_seed_length());
    _fillRandom(result);
    return result;
  }

  String sign(String message) {
    final units = utf8.encode(message);
    final outLen = olm_pk_signature_length();
    final mem = allocate<Uint8>(count: units.length + outLen);
    final outMem = mem.elementAt(units.length);
    try {
      mem.asTypedList(units.length).setAll(0, units);
      olm_pk_sign(_inst, mem, units.length, outMem, outLen);
      return utf8.decode(outMem.asTypedList(outLen));
    } finally {
      ffi.free(mem);
    }
  }
}
