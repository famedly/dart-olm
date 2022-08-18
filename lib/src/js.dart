// Auto-generated file.

@JS('Olm')
library js;

import 'dart:async';
import 'dart:js_util';
import 'dart:typed_data';

import 'package:js/js.dart';

@JS("init")
external dynamic _init();

Future<void> init() {
  return promiseToFuture(_init());
}

@JS()
external List<int> get_library_version();

@JS()
class EncryptResult {
  external int type;
  external String body;
}

@JS()
class DecryptResult {
  external int message_index;
  external String plaintext;
}

@JS()
class Account {
  external Account();
  external void free();
  external void create();
  external String identity_keys();
  external String one_time_keys();
  external String fallback_key();
  external String pickle(String key);
  external void unpickle(String key, String data);
  external void generate_one_time_keys(int count);
  external void generate_fallback_key();
  external void remove_one_time_keys(Session session);
  external void mark_keys_as_published();
  external int max_number_of_one_time_keys();
  external String sign(String message);
}

@JS()
class Session {
  external Session();
  external void free();
  external String pickle(String key);
  external void unpickle(String key, String data);
  external void create_outbound(
      Account account, String identity_key, String one_time_key);
  external void create_inbound(Account account, String message);
  external void create_inbound_from(
      Account account, String identity_key, String one_time_key);
  external String session_id();
  external bool has_received_message();
  external int encrypt_message_type();
  external bool matches_inbound(String message);
  external bool matches_inbound_from(String identity_key, String message);
  external EncryptResult encrypt(String plaintext);
  external String decrypt(int message_type, String message);
}

@JS()
class Utility {
  external Utility();
  external void free();
  external String sha256(String input);

  /// Not implemented for Web in upstream olm.
  external String sha256_bytes(Uint8List input);

  external void ed25519_verify(String key, String message, String signature);
}

@JS()
class InboundGroupSession {
  external InboundGroupSession();
  external void free();
  external String pickle(String key);
  external void unpickle(String key, String data);
  external void create(String session_key);
  external void import_session(String session_key);
  external DecryptResult decrypt(String message);
  external String session_id();
  external int first_known_index();
  external String export_session(int message_index);
}

@JS()
class OutboundGroupSession {
  external OutboundGroupSession();
  external void free();
  external String pickle(String key);
  external void unpickle(String key, String data);
  external void create();
  external String encrypt(String plaintext);
  external String session_id();
  external int message_index();
  external String session_key();
}

@JS()
class SAS {
  external SAS();
  external void free();
  external String get_pubkey();
  external void set_their_key(String their_key);
  external Uint8List generate_bytes(String info, int length);
  external String calculate_mac(String input, String info);
  external String calculate_mac_long_kdf(String input, String info);
}

@JS()
class PkEncryptResult {
  external String ciphertext;
  external String mac;
  external String ephemeral;
}

@JS()
class PkEncryption {
  external PkEncryption();
  external void free();
  external void set_recipient_key(String key);
  external PkEncryptResult encrypt(String plaintext);
}

@JS()
class PkDecryption {
  external PkDecryption();
  external void free();
  external String init_with_private_key(Uint8List private_key);
  external String generate_key();
  external Uint8List get_private_key();
  external String pickle(String key);
  external String unpickle(String key, String data);
  external String decrypt(String ephemeral_key, String mac, String ciphertext);
}

@JS()
class PkSigning {
  external PkSigning();
  external void free();
  external String init_with_seed(Uint8List seed);
  external Uint8List generate_seed();
  external String sign(String message);
}
