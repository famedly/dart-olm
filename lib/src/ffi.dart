// Auto-generated file.

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'ffi_base.dart';

final olm_inbound_group_session_size =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_inbound_group_session_size');

final olm_inbound_group_session = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(
        Pointer<Uint8> memory)>('olm_inbound_group_session');

final olm_inbound_group_session_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> session),
    Pointer<Utf8> Function(
        Pointer<NativeType> session)>('olm_inbound_group_session_last_error');

int olm_clear_inbound_group_session(Pointer<NativeType> session) {
  int result = _olm_clear_inbound_group_session_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_clear_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_clear_inbound_group_session');

int olm_pickle_inbound_group_session_length(Pointer<NativeType> session) {
  int result = _olm_pickle_inbound_group_session_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_pickle_inbound_group_session_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> session),
            int Function(Pointer<NativeType> session)>(
        'olm_pickle_inbound_group_session_length');

int olm_pickle_inbound_group_session(
    Pointer<NativeType> session,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> pickled,
    int pickled_length) {
  int result = _olm_pickle_inbound_group_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_pickle_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_pickle_inbound_group_session');

int olm_unpickle_inbound_group_session(
    Pointer<NativeType> session,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> pickled,
    int pickled_length) {
  int result = _olm_unpickle_inbound_group_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_unpickle_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_unpickle_inbound_group_session');

int olm_init_inbound_group_session(Pointer<NativeType> session,
    Pointer<Uint8> session_key, int session_key_length) {
  int result = _olm_init_inbound_group_session_unchecked(
      session, session_key, session_key_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_init_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> session_key,
        IntPtr session_key_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> session_key,
        int session_key_length)>('olm_init_inbound_group_session');

int olm_import_inbound_group_session(Pointer<NativeType> session,
    Pointer<Uint8> session_key, int session_key_length) {
  int result = _olm_import_inbound_group_session_unchecked(
      session, session_key, session_key_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_import_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> session_key,
        IntPtr session_key_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> session_key,
        int session_key_length)>('olm_import_inbound_group_session');

int olm_group_decrypt_max_plaintext_length(
    Pointer<NativeType> session, Pointer<Uint8> message, int message_length) {
  int result = _olm_group_decrypt_max_plaintext_length_unchecked(
      session, message, message_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_group_decrypt_max_plaintext_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> message,
        IntPtr message_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> message,
        int message_length)>('olm_group_decrypt_max_plaintext_length');

int olm_group_decrypt(
    Pointer<NativeType> session,
    Pointer<Uint8> message,
    int message_length,
    Pointer<Uint8> plaintext,
    int max_plaintext_length,
    Pointer<Uint32> message_index) {
  int result = _olm_group_decrypt_unchecked(session, message, message_length,
      plaintext, max_plaintext_length, message_index);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_group_decrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        Pointer<Uint8> message,
        IntPtr message_length,
        Pointer<Uint8> plaintext,
        IntPtr max_plaintext_length,
        Pointer<Uint32> message_index),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> message,
        int message_length,
        Pointer<Uint8> plaintext,
        int max_plaintext_length,
        Pointer<Uint32> message_index)>('olm_group_decrypt');

int olm_inbound_group_session_id_length(Pointer<NativeType> session) {
  int result = _olm_inbound_group_session_id_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_inbound_group_session_id_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_inbound_group_session_id_length');

int olm_inbound_group_session_id(
    Pointer<NativeType> session, Pointer<Uint8> id, int id_length) {
  int result = _olm_inbound_group_session_id_unchecked(session, id, id_length);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_inbound_group_session_id_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session, Pointer<Uint8> id, IntPtr id_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> id,
        int id_length)>('olm_inbound_group_session_id');

final olm_inbound_group_session_first_known_index = libolm.lookupFunction<
        Uint32 Function(Pointer<NativeType> session),
        int Function(Pointer<NativeType> session)>(
    'olm_inbound_group_session_first_known_index');

final olm_inbound_group_session_is_verified = libolm.lookupFunction<
    Int32 Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_inbound_group_session_is_verified');

int olm_export_inbound_group_session_length(Pointer<NativeType> session) {
  int result = _olm_export_inbound_group_session_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_export_inbound_group_session_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> session),
            int Function(Pointer<NativeType> session)>(
        'olm_export_inbound_group_session_length');

int olm_export_inbound_group_session(Pointer<NativeType> session,
    Pointer<Uint8> key, int key_length, int message_index) {
  int result = _olm_export_inbound_group_session_unchecked(
      session, key, key_length, message_index);
  if (result == olm_error())
    throw_olm(olm_inbound_group_session_last_error(session));
  return result;
}

final _olm_export_inbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Uint32 message_index),
    int Function(Pointer<NativeType> session, Pointer<Uint8> key,
        int key_length, int message_index)>('olm_export_inbound_group_session');

final olm_outbound_group_session_size =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_outbound_group_session_size');

final olm_outbound_group_session = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(
        Pointer<Uint8> memory)>('olm_outbound_group_session');

final olm_outbound_group_session_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> session),
    Pointer<Utf8> Function(
        Pointer<NativeType> session)>('olm_outbound_group_session_last_error');

int olm_clear_outbound_group_session(Pointer<NativeType> session) {
  int result = _olm_clear_outbound_group_session_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_clear_outbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_clear_outbound_group_session');

int olm_pickle_outbound_group_session_length(Pointer<NativeType> session) {
  int result = _olm_pickle_outbound_group_session_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_pickle_outbound_group_session_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> session),
            int Function(Pointer<NativeType> session)>(
        'olm_pickle_outbound_group_session_length');

int olm_pickle_outbound_group_session(
    Pointer<NativeType> session,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> pickled,
    int pickled_length) {
  int result = _olm_pickle_outbound_group_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_pickle_outbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_pickle_outbound_group_session');

int olm_unpickle_outbound_group_session(
    Pointer<NativeType> session,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> pickled,
    int pickled_length) {
  int result = _olm_unpickle_outbound_group_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_unpickle_outbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_unpickle_outbound_group_session');

int olm_init_outbound_group_session_random_length(Pointer<NativeType> session) {
  int result =
      _olm_init_outbound_group_session_random_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_init_outbound_group_session_random_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> session),
            int Function(Pointer<NativeType> session)>(
        'olm_init_outbound_group_session_random_length');

int olm_init_outbound_group_session(
    Pointer<NativeType> session, Pointer<Uint8> random, int random_length) {
  int result = _olm_init_outbound_group_session_unchecked(
      session, random, random_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_init_outbound_group_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> random,
        IntPtr random_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> random,
        int random_length)>('olm_init_outbound_group_session');

int olm_group_encrypt_message_length(
    Pointer<NativeType> session, int plaintext_length) {
  int result =
      _olm_group_encrypt_message_length_unchecked(session, plaintext_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_group_encrypt_message_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, IntPtr plaintext_length),
    int Function(Pointer<NativeType> session,
        int plaintext_length)>('olm_group_encrypt_message_length');

int olm_group_encrypt(Pointer<NativeType> session, Pointer<Uint8> plaintext,
    int plaintext_length, Pointer<Uint8> message, int message_length) {
  int result = _olm_group_encrypt_unchecked(
      session, plaintext, plaintext_length, message, message_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_group_encrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> plaintext,
        IntPtr plaintext_length, Pointer<Uint8> message, IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> plaintext,
        int plaintext_length,
        Pointer<Uint8> message,
        int message_length)>('olm_group_encrypt');

int olm_outbound_group_session_id_length(Pointer<NativeType> session) {
  int result = _olm_outbound_group_session_id_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_outbound_group_session_id_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_outbound_group_session_id_length');

int olm_outbound_group_session_id(
    Pointer<NativeType> session, Pointer<Uint8> id, int id_length) {
  int result = _olm_outbound_group_session_id_unchecked(session, id, id_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_outbound_group_session_id_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session, Pointer<Uint8> id, IntPtr id_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> id,
        int id_length)>('olm_outbound_group_session_id');

final olm_outbound_group_session_message_index = libolm.lookupFunction<
        Uint32 Function(Pointer<NativeType> session),
        int Function(Pointer<NativeType> session)>(
    'olm_outbound_group_session_message_index');

int olm_outbound_group_session_key_length(Pointer<NativeType> session) {
  int result = _olm_outbound_group_session_key_length_unchecked(session);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_outbound_group_session_key_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_outbound_group_session_key_length');

int olm_outbound_group_session_key(
    Pointer<NativeType> session, Pointer<Uint8> key, int key_length) {
  int result =
      _olm_outbound_group_session_key_unchecked(session, key, key_length);
  if (result == olm_error())
    throw_olm(olm_outbound_group_session_last_error(session));
  return result;
}

final _olm_outbound_group_session_key_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session, Pointer<Uint8> key, IntPtr key_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> key,
        int key_length)>('olm_outbound_group_session_key');

final olm_get_library_version = libolm.lookupFunction<
    Void Function(
        Pointer<Uint8> major, Pointer<Uint8> minor, Pointer<Uint8> patch),
    void Function(Pointer<Uint8> major, Pointer<Uint8> minor,
        Pointer<Uint8> patch)>('olm_get_library_version');

final olm_account_size = libolm
    .lookupFunction<IntPtr Function(), int Function()>('olm_account_size');

final olm_session_size = libolm
    .lookupFunction<IntPtr Function(), int Function()>('olm_session_size');

final olm_utility_size = libolm
    .lookupFunction<IntPtr Function(), int Function()>('olm_utility_size');

final olm_account = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_account');

final olm_session = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_session');

final olm_utility = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_utility');

final olm_error =
    libolm.lookupFunction<IntPtr Function(), int Function()>('olm_error');

final olm_account_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> account),
    Pointer<Utf8> Function(
        Pointer<NativeType> account)>('olm_account_last_error');

final olm_session_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> session),
    Pointer<Utf8> Function(
        Pointer<NativeType> session)>('olm_session_last_error');

final olm_utility_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> utility),
    Pointer<Utf8> Function(
        Pointer<NativeType> utility)>('olm_utility_last_error');

int olm_clear_account(Pointer<NativeType> account) {
  int result = _olm_clear_account_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_clear_account_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(Pointer<NativeType> account)>('olm_clear_account');

int olm_clear_session(Pointer<NativeType> session) {
  int result = _olm_clear_session_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_clear_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(Pointer<NativeType> session)>('olm_clear_session');

int olm_clear_utility(Pointer<NativeType> utility) {
  int result = _olm_clear_utility_unchecked(utility);
  if (result == olm_error()) throw_olm(olm_utility_last_error(utility));
  return result;
}

final _olm_clear_utility_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> utility),
    int Function(Pointer<NativeType> utility)>('olm_clear_utility');

int olm_pickle_account_length(Pointer<NativeType> account) {
  int result = _olm_pickle_account_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_pickle_account_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(Pointer<NativeType> account)>('olm_pickle_account_length');

int olm_pickle_session_length(Pointer<NativeType> session) {
  int result = _olm_pickle_session_length_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_pickle_session_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(Pointer<NativeType> session)>('olm_pickle_session_length');

int olm_pickle_account(Pointer<NativeType> account, Pointer<Uint8> key,
    int key_length, Pointer<Uint8> pickled, int pickled_length) {
  int result = _olm_pickle_account_unchecked(
      account, key, key_length, pickled, pickled_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_pickle_account_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> account,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_pickle_account');

int olm_pickle_session(Pointer<NativeType> session, Pointer<Uint8> key,
    int key_length, Pointer<Uint8> pickled, int pickled_length) {
  int result = _olm_pickle_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_pickle_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_pickle_session');

int olm_unpickle_account(Pointer<NativeType> account, Pointer<Uint8> key,
    int key_length, Pointer<Uint8> pickled, int pickled_length) {
  int result = _olm_unpickle_account_unchecked(
      account, key, key_length, pickled, pickled_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_unpickle_account_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> account,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_unpickle_account');

int olm_unpickle_session(Pointer<NativeType> session, Pointer<Uint8> key,
    int key_length, Pointer<Uint8> pickled, int pickled_length) {
  int result = _olm_unpickle_session_unchecked(
      session, key, key_length, pickled, pickled_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_unpickle_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_unpickle_session');

int olm_create_account_random_length(Pointer<NativeType> account) {
  int result = _olm_create_account_random_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_create_account_random_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(
        Pointer<NativeType> account)>('olm_create_account_random_length');

int olm_create_account(
    Pointer<NativeType> account, Pointer<Uint8> random, int random_length) {
  int result = _olm_create_account_unchecked(account, random, random_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_create_account_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> random,
        IntPtr random_length),
    int Function(Pointer<NativeType> account, Pointer<Uint8> random,
        int random_length)>('olm_create_account');

int olm_account_identity_keys_length(Pointer<NativeType> account) {
  int result = _olm_account_identity_keys_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_identity_keys_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(
        Pointer<NativeType> account)>('olm_account_identity_keys_length');

int olm_account_identity_keys(Pointer<NativeType> account,
    Pointer<Uint8> identity_keys, int identity_key_length) {
  int result = _olm_account_identity_keys_unchecked(
      account, identity_keys, identity_key_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_identity_keys_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> identity_keys,
        IntPtr identity_key_length),
    int Function(Pointer<NativeType> account, Pointer<Uint8> identity_keys,
        int identity_key_length)>('olm_account_identity_keys');

int olm_account_signature_length(Pointer<NativeType> account) {
  int result = _olm_account_signature_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_signature_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(Pointer<NativeType> account)>('olm_account_signature_length');

int olm_account_sign(Pointer<NativeType> account, Pointer<Uint8> message,
    int message_length, Pointer<Uint8> signature, int signature_length) {
  int result = _olm_account_sign_unchecked(
      account, message, message_length, signature, signature_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_sign_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> account,
        Pointer<Uint8> message,
        IntPtr message_length,
        Pointer<Uint8> signature,
        IntPtr signature_length),
    int Function(
        Pointer<NativeType> account,
        Pointer<Uint8> message,
        int message_length,
        Pointer<Uint8> signature,
        int signature_length)>('olm_account_sign');

int olm_account_one_time_keys_length(Pointer<NativeType> account) {
  int result = _olm_account_one_time_keys_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_one_time_keys_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(
        Pointer<NativeType> account)>('olm_account_one_time_keys_length');

int olm_account_one_time_keys(Pointer<NativeType> account,
    Pointer<Uint8> one_time_keys, int one_time_keys_length) {
  int result = _olm_account_one_time_keys_unchecked(
      account, one_time_keys, one_time_keys_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_one_time_keys_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> one_time_keys,
        IntPtr one_time_keys_length),
    int Function(Pointer<NativeType> account, Pointer<Uint8> one_time_keys,
        int one_time_keys_length)>('olm_account_one_time_keys');

int olm_account_mark_keys_as_published(Pointer<NativeType> account) {
  int result = _olm_account_mark_keys_as_published_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_mark_keys_as_published_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(
        Pointer<NativeType> account)>('olm_account_mark_keys_as_published');

int olm_account_max_number_of_one_time_keys(Pointer<NativeType> account) {
  int result = _olm_account_max_number_of_one_time_keys_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_max_number_of_one_time_keys_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> account),
            int Function(Pointer<NativeType> account)>(
        'olm_account_max_number_of_one_time_keys');

int olm_account_generate_one_time_keys_random_length(
    Pointer<NativeType> account, int number_of_keys) {
  int result = _olm_account_generate_one_time_keys_random_length_unchecked(
      account, number_of_keys);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_generate_one_time_keys_random_length_unchecked =
    libolm.lookupFunction<
            IntPtr Function(Pointer<NativeType> account, IntPtr number_of_keys),
            int Function(Pointer<NativeType> account, int number_of_keys)>(
        'olm_account_generate_one_time_keys_random_length');

int olm_account_generate_one_time_keys(Pointer<NativeType> account,
    int number_of_keys, Pointer<Uint8> random, int random_length) {
  int result = _olm_account_generate_one_time_keys_unchecked(
      account, number_of_keys, random, random_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_generate_one_time_keys_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, IntPtr number_of_keys,
        Pointer<Uint8> random, IntPtr random_length),
    int Function(
        Pointer<NativeType> account,
        int number_of_keys,
        Pointer<Uint8> random,
        int random_length)>('olm_account_generate_one_time_keys');

int olm_account_generate_fallback_key_random_length(
    Pointer<NativeType> account) {
  int result =
      _olm_account_generate_fallback_key_random_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_generate_fallback_key_random_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> account),
            int Function(Pointer<NativeType> account)>(
        'olm_account_generate_fallback_key_random_length');

int olm_account_generate_fallback_key(
    Pointer<NativeType> account, Pointer<Uint8> random, int random_length) {
  int result = _olm_account_generate_fallback_key_unchecked(
      account, random, random_length);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_generate_fallback_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> random,
        IntPtr random_length),
    int Function(Pointer<NativeType> account, Pointer<Uint8> random,
        int random_length)>('olm_account_generate_fallback_key');

int olm_account_fallback_key_length(Pointer<NativeType> account) {
  int result = _olm_account_fallback_key_length_unchecked(account);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_fallback_key_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account),
    int Function(
        Pointer<NativeType> account)>('olm_account_fallback_key_length');

int olm_account_fallback_key(Pointer<NativeType> account,
    Pointer<Uint8> fallback_key, int fallback_key_size) {
  int result = _olm_account_fallback_key_unchecked(
      account, fallback_key, fallback_key_size);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_account_fallback_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<Uint8> fallback_key,
        IntPtr fallback_key_size),
    int Function(Pointer<NativeType> account, Pointer<Uint8> fallback_key,
        int fallback_key_size)>('olm_account_fallback_key');

int olm_create_outbound_session_random_length(Pointer<NativeType> session) {
  int result = _olm_create_outbound_session_random_length_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_create_outbound_session_random_length_unchecked =
    libolm.lookupFunction<IntPtr Function(Pointer<NativeType> session),
            int Function(Pointer<NativeType> session)>(
        'olm_create_outbound_session_random_length');

int olm_create_outbound_session(
    Pointer<NativeType> session,
    Pointer<NativeType> account,
    Pointer<Uint8> their_identity_key,
    int their_identity_key_length,
    Pointer<Uint8> their_one_time_key,
    int their_one_time_key_length,
    Pointer<Uint8> random,
    int random_length) {
  int result = _olm_create_outbound_session_unchecked(
      session,
      account,
      their_identity_key,
      their_identity_key_length,
      their_one_time_key,
      their_one_time_key_length,
      random,
      random_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_create_outbound_session_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        Pointer<NativeType> account,
        Pointer<Uint8> their_identity_key,
        IntPtr their_identity_key_length,
        Pointer<Uint8> their_one_time_key,
        IntPtr their_one_time_key_length,
        Pointer<Uint8> random,
        IntPtr random_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<NativeType> account,
        Pointer<Uint8> their_identity_key,
        int their_identity_key_length,
        Pointer<Uint8> their_one_time_key,
        int their_one_time_key_length,
        Pointer<Uint8> random,
        int random_length)>('olm_create_outbound_session');

int olm_create_inbound_session(
    Pointer<NativeType> session,
    Pointer<NativeType> account,
    Pointer<Uint8> one_time_key_message,
    int message_length) {
  int result = _olm_create_inbound_session_unchecked(
      session, account, one_time_key_message, message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_create_inbound_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, Pointer<NativeType> account,
        Pointer<Uint8> one_time_key_message, IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<NativeType> account,
        Pointer<Uint8> one_time_key_message,
        int message_length)>('olm_create_inbound_session');

int olm_create_inbound_session_from(
    Pointer<NativeType> session,
    Pointer<NativeType> account,
    Pointer<Uint8> their_identity_key,
    int their_identity_key_length,
    Pointer<Uint8> one_time_key_message,
    int message_length) {
  int result = _olm_create_inbound_session_from_unchecked(
      session,
      account,
      their_identity_key,
      their_identity_key_length,
      one_time_key_message,
      message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_create_inbound_session_from_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        Pointer<NativeType> account,
        Pointer<Uint8> their_identity_key,
        IntPtr their_identity_key_length,
        Pointer<Uint8> one_time_key_message,
        IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<NativeType> account,
        Pointer<Uint8> their_identity_key,
        int their_identity_key_length,
        Pointer<Uint8> one_time_key_message,
        int message_length)>('olm_create_inbound_session_from');

int olm_session_id_length(Pointer<NativeType> session) {
  int result = _olm_session_id_length_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_session_id_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(Pointer<NativeType> session)>('olm_session_id_length');

int olm_session_id(
    Pointer<NativeType> session, Pointer<Uint8> id, int id_length) {
  int result = _olm_session_id_unchecked(session, id, id_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_session_id_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session, Pointer<Uint8> id, IntPtr id_length),
    int Function(Pointer<NativeType> session, Pointer<Uint8> id,
        int id_length)>('olm_session_id');

final olm_session_has_received_message = libolm.lookupFunction<
    Int32 Function(Pointer<NativeType> session),
    int Function(
        Pointer<NativeType> session)>('olm_session_has_received_message');

final olm_session_describe = libolm.lookupFunction<
    Void Function(
        Pointer<NativeType> session, Pointer<Utf8> buf, IntPtr buflen),
    void Function(Pointer<NativeType> session, Pointer<Utf8> buf,
        int buflen)>('olm_session_describe');

int olm_matches_inbound_session(Pointer<NativeType> session,
    Pointer<Uint8> one_time_key_message, int message_length) {
  int result = _olm_matches_inbound_session_unchecked(
      session, one_time_key_message, message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_matches_inbound_session_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session,
        Pointer<Uint8> one_time_key_message, IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> one_time_key_message,
        int message_length)>('olm_matches_inbound_session');

int olm_matches_inbound_session_from(
    Pointer<NativeType> session,
    Pointer<Uint8> their_identity_key,
    int their_identity_key_length,
    Pointer<Uint8> one_time_key_message,
    int message_length) {
  int result = _olm_matches_inbound_session_from_unchecked(
      session,
      their_identity_key,
      their_identity_key_length,
      one_time_key_message,
      message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_matches_inbound_session_from_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        Pointer<Uint8> their_identity_key,
        IntPtr their_identity_key_length,
        Pointer<Uint8> one_time_key_message,
        IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> their_identity_key,
        int their_identity_key_length,
        Pointer<Uint8> one_time_key_message,
        int message_length)>('olm_matches_inbound_session_from');

int olm_remove_one_time_keys(
    Pointer<NativeType> account, Pointer<NativeType> session) {
  int result = _olm_remove_one_time_keys_unchecked(account, session);
  if (result == olm_error()) throw_olm(olm_account_last_error(account));
  return result;
}

final _olm_remove_one_time_keys_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> account, Pointer<NativeType> session),
    int Function(Pointer<NativeType> account,
        Pointer<NativeType> session)>('olm_remove_one_time_keys');

int olm_encrypt_message_type(Pointer<NativeType> session) {
  int result = _olm_encrypt_message_type_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_encrypt_message_type_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(Pointer<NativeType> session)>('olm_encrypt_message_type');

int olm_encrypt_random_length(Pointer<NativeType> session) {
  int result = _olm_encrypt_random_length_unchecked(session);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_encrypt_random_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session),
    int Function(Pointer<NativeType> session)>('olm_encrypt_random_length');

int olm_encrypt_message_length(
    Pointer<NativeType> session, int plaintext_length) {
  int result = _olm_encrypt_message_length_unchecked(session, plaintext_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_encrypt_message_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, IntPtr plaintext_length),
    int Function(Pointer<NativeType> session,
        int plaintext_length)>('olm_encrypt_message_length');

int olm_encrypt(
    Pointer<NativeType> session,
    Pointer<Uint8> plaintext,
    int plaintext_length,
    Pointer<Uint8> random,
    int random_length,
    Pointer<Uint8> message,
    int message_length) {
  int result = _olm_encrypt_unchecked(session, plaintext, plaintext_length,
      random, random_length, message, message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_encrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        Pointer<Uint8> plaintext,
        IntPtr plaintext_length,
        Pointer<Uint8> random,
        IntPtr random_length,
        Pointer<Uint8> message,
        IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        Pointer<Uint8> plaintext,
        int plaintext_length,
        Pointer<Uint8> random,
        int random_length,
        Pointer<Uint8> message,
        int message_length)>('olm_encrypt');

int olm_decrypt_max_plaintext_length(Pointer<NativeType> session,
    int message_type, Pointer<Uint8> message, int message_length) {
  int result = _olm_decrypt_max_plaintext_length_unchecked(
      session, message_type, message, message_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_decrypt_max_plaintext_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> session, IntPtr message_type,
        Pointer<Uint8> message, IntPtr message_length),
    int Function(
        Pointer<NativeType> session,
        int message_type,
        Pointer<Uint8> message,
        int message_length)>('olm_decrypt_max_plaintext_length');

int olm_decrypt(
    Pointer<NativeType> session,
    int message_type,
    Pointer<Uint8> message,
    int message_length,
    Pointer<Uint8> plaintext,
    int max_plaintext_length) {
  int result = _olm_decrypt_unchecked(session, message_type, message,
      message_length, plaintext, max_plaintext_length);
  if (result == olm_error()) throw_olm(olm_session_last_error(session));
  return result;
}

final _olm_decrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> session,
        IntPtr message_type,
        Pointer<Uint8> message,
        IntPtr message_length,
        Pointer<Uint8> plaintext,
        IntPtr max_plaintext_length),
    int Function(
        Pointer<NativeType> session,
        int message_type,
        Pointer<Uint8> message,
        int message_length,
        Pointer<Uint8> plaintext,
        int max_plaintext_length)>('olm_decrypt');

int olm_sha256_length(Pointer<NativeType> utility) {
  int result = _olm_sha256_length_unchecked(utility);
  if (result == olm_error()) throw_olm(olm_utility_last_error(utility));
  return result;
}

final _olm_sha256_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> utility),
    int Function(Pointer<NativeType> utility)>('olm_sha256_length');

int olm_sha256(Pointer<NativeType> utility, Pointer<Uint8> input,
    int input_length, Pointer<Uint8> output, int output_length) {
  int result = _olm_sha256_unchecked(
      utility, input, input_length, output, output_length);
  if (result == olm_error()) throw_olm(olm_utility_last_error(utility));
  return result;
}

final _olm_sha256_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> utility, Pointer<Uint8> input,
        IntPtr input_length, Pointer<Uint8> output, IntPtr output_length),
    int Function(
        Pointer<NativeType> utility,
        Pointer<Uint8> input,
        int input_length,
        Pointer<Uint8> output,
        int output_length)>('olm_sha256');

int olm_ed25519_verify(
    Pointer<NativeType> utility,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> message,
    int message_length,
    Pointer<Uint8> signature,
    int signature_length) {
  int result = _olm_ed25519_verify_unchecked(utility, key, key_length, message,
      message_length, signature, signature_length);
  if (result == olm_error()) throw_olm(olm_utility_last_error(utility));
  return result;
}

final _olm_ed25519_verify_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> utility,
        Pointer<Uint8> key,
        IntPtr key_length,
        Pointer<Uint8> message,
        IntPtr message_length,
        Pointer<Uint8> signature,
        IntPtr signature_length),
    int Function(
        Pointer<NativeType> utility,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> message,
        int message_length,
        Pointer<Uint8> signature,
        int signature_length)>('olm_ed25519_verify');

final olm_sas_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> sas),
    Pointer<Utf8> Function(Pointer<NativeType> sas)>('olm_sas_last_error');

final olm_sas_size =
    libolm.lookupFunction<IntPtr Function(), int Function()>('olm_sas_size');

final olm_sas = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_sas');

int olm_clear_sas(Pointer<NativeType> sas) {
  int result = _olm_clear_sas_unchecked(sas);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_clear_sas_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas),
    int Function(Pointer<NativeType> sas)>('olm_clear_sas');

int olm_create_sas_random_length(Pointer<NativeType> sas) {
  int result = _olm_create_sas_random_length_unchecked(sas);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_create_sas_random_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas),
    int Function(Pointer<NativeType> sas)>('olm_create_sas_random_length');

int olm_create_sas(
    Pointer<NativeType> sas, Pointer<Uint8> random, int random_length) {
  int result = _olm_create_sas_unchecked(sas, random, random_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_create_sas_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> sas, Pointer<Uint8> random, IntPtr random_length),
    int Function(Pointer<NativeType> sas, Pointer<Uint8> random,
        int random_length)>('olm_create_sas');

int olm_sas_pubkey_length(Pointer<NativeType> sas) {
  int result = _olm_sas_pubkey_length_unchecked(sas);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_pubkey_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas),
    int Function(Pointer<NativeType> sas)>('olm_sas_pubkey_length');

int olm_sas_get_pubkey(
    Pointer<NativeType> sas, Pointer<Uint8> pubkey, int pubkey_length) {
  int result = _olm_sas_get_pubkey_unchecked(sas, pubkey, pubkey_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_get_pubkey_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> sas, Pointer<Uint8> pubkey, IntPtr pubkey_length),
    int Function(Pointer<NativeType> sas, Pointer<Uint8> pubkey,
        int pubkey_length)>('olm_sas_get_pubkey');

int olm_sas_set_their_key(
    Pointer<NativeType> sas, Pointer<Uint8> their_key, int their_key_length) {
  int result =
      _olm_sas_set_their_key_unchecked(sas, their_key, their_key_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_set_their_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas, Pointer<Uint8> their_key,
        IntPtr their_key_length),
    int Function(Pointer<NativeType> sas, Pointer<Uint8> their_key,
        int their_key_length)>('olm_sas_set_their_key');

final olm_sas_is_their_key_set = libolm.lookupFunction<
    Int32 Function(Pointer<NativeType> sas),
    int Function(Pointer<NativeType> sas)>('olm_sas_is_their_key_set');

int olm_sas_generate_bytes(Pointer<NativeType> sas, Pointer<Uint8> info,
    int info_length, Pointer<Uint8> output, int output_length) {
  int result = _olm_sas_generate_bytes_unchecked(
      sas, info, info_length, output, output_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_generate_bytes_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas, Pointer<Uint8> info,
        IntPtr info_length, Pointer<Uint8> output, IntPtr output_length),
    int Function(Pointer<NativeType> sas, Pointer<Uint8> info, int info_length,
        Pointer<Uint8> output, int output_length)>('olm_sas_generate_bytes');

int olm_sas_mac_length(Pointer<NativeType> sas) {
  int result = _olm_sas_mac_length_unchecked(sas);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_mac_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sas),
    int Function(Pointer<NativeType> sas)>('olm_sas_mac_length');

int olm_sas_calculate_mac(
    Pointer<NativeType> sas,
    Pointer<Uint8> input,
    int input_length,
    Pointer<Uint8> info,
    int info_length,
    Pointer<Uint8> mac,
    int mac_length) {
  int result = _olm_sas_calculate_mac_unchecked(
      sas, input, input_length, info, info_length, mac, mac_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_calculate_mac_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> sas,
        Pointer<Uint8> input,
        IntPtr input_length,
        Pointer<Uint8> info,
        IntPtr info_length,
        Pointer<Uint8> mac,
        IntPtr mac_length),
    int Function(
        Pointer<NativeType> sas,
        Pointer<Uint8> input,
        int input_length,
        Pointer<Uint8> info,
        int info_length,
        Pointer<Uint8> mac,
        int mac_length)>('olm_sas_calculate_mac');

int olm_sas_calculate_mac_long_kdf(
    Pointer<NativeType> sas,
    Pointer<Uint8> input,
    int input_length,
    Pointer<Uint8> info,
    int info_length,
    Pointer<Uint8> mac,
    int mac_length) {
  int result = _olm_sas_calculate_mac_long_kdf_unchecked(
      sas, input, input_length, info, info_length, mac, mac_length);
  if (result == olm_error()) throw_olm(olm_sas_last_error(sas));
  return result;
}

final _olm_sas_calculate_mac_long_kdf_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> sas,
        Pointer<Uint8> input,
        IntPtr input_length,
        Pointer<Uint8> info,
        IntPtr info_length,
        Pointer<Uint8> mac,
        IntPtr mac_length),
    int Function(
        Pointer<NativeType> sas,
        Pointer<Uint8> input,
        int input_length,
        Pointer<Uint8> info,
        int info_length,
        Pointer<Uint8> mac,
        int mac_length)>('olm_sas_calculate_mac_long_kdf');

final olm_pk_encryption_size =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_encryption_size');

final olm_pk_encryption = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_pk_encryption');

final olm_pk_encryption_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> encryption),
    Pointer<Utf8> Function(
        Pointer<NativeType> encryption)>('olm_pk_encryption_last_error');

int olm_clear_pk_encryption(Pointer<NativeType> encryption) {
  int result = _olm_clear_pk_encryption_unchecked(encryption);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_clear_pk_encryption_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> encryption),
    int Function(Pointer<NativeType> encryption)>('olm_clear_pk_encryption');

int olm_pk_encryption_set_recipient_key(Pointer<NativeType> encryption,
    Pointer<Uint8> public_key, int public_key_length) {
  int result = _olm_pk_encryption_set_recipient_key_unchecked(
      encryption, public_key, public_key_length);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_pk_encryption_set_recipient_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> encryption, Pointer<Uint8> public_key,
        IntPtr public_key_length),
    int Function(Pointer<NativeType> encryption, Pointer<Uint8> public_key,
        int public_key_length)>('olm_pk_encryption_set_recipient_key');

int olm_pk_ciphertext_length(
    Pointer<NativeType> encryption, int plaintext_length) {
  int result =
      _olm_pk_ciphertext_length_unchecked(encryption, plaintext_length);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_pk_ciphertext_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> encryption, IntPtr plaintext_length),
    int Function(Pointer<NativeType> encryption,
        int plaintext_length)>('olm_pk_ciphertext_length');

int olm_pk_mac_length(Pointer<NativeType> encryption) {
  int result = _olm_pk_mac_length_unchecked(encryption);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_pk_mac_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> encryption),
    int Function(Pointer<NativeType> encryption)>('olm_pk_mac_length');

final olm_pk_key_length = libolm
    .lookupFunction<IntPtr Function(), int Function()>('olm_pk_key_length');

int olm_pk_encrypt_random_length(Pointer<NativeType> encryption) {
  int result = _olm_pk_encrypt_random_length_unchecked(encryption);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_pk_encrypt_random_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> encryption),
    int Function(
        Pointer<NativeType> encryption)>('olm_pk_encrypt_random_length');

int olm_pk_encrypt(
    Pointer<NativeType> encryption,
    Pointer<Uint8> plaintext,
    int plaintext_length,
    Pointer<Uint8> ciphertext,
    int ciphertext_length,
    Pointer<Uint8> mac,
    int mac_length,
    Pointer<Uint8> ephemeral_key,
    int ephemeral_key_size,
    Pointer<Uint8> random,
    int random_length) {
  int result = _olm_pk_encrypt_unchecked(
      encryption,
      plaintext,
      plaintext_length,
      ciphertext,
      ciphertext_length,
      mac,
      mac_length,
      ephemeral_key,
      ephemeral_key_size,
      random,
      random_length);
  if (result == olm_error())
    throw_olm(olm_pk_encryption_last_error(encryption));
  return result;
}

final _olm_pk_encrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> encryption,
        Pointer<Uint8> plaintext,
        IntPtr plaintext_length,
        Pointer<Uint8> ciphertext,
        IntPtr ciphertext_length,
        Pointer<Uint8> mac,
        IntPtr mac_length,
        Pointer<Uint8> ephemeral_key,
        IntPtr ephemeral_key_size,
        Pointer<Uint8> random,
        IntPtr random_length),
    int Function(
        Pointer<NativeType> encryption,
        Pointer<Uint8> plaintext,
        int plaintext_length,
        Pointer<Uint8> ciphertext,
        int ciphertext_length,
        Pointer<Uint8> mac,
        int mac_length,
        Pointer<Uint8> ephemeral_key,
        int ephemeral_key_size,
        Pointer<Uint8> random,
        int random_length)>('olm_pk_encrypt');

final olm_pk_decryption_size =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_decryption_size');

final olm_pk_decryption = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_pk_decryption');

final olm_pk_decryption_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> decryption),
    Pointer<Utf8> Function(
        Pointer<NativeType> decryption)>('olm_pk_decryption_last_error');

int olm_clear_pk_decryption(Pointer<NativeType> decryption) {
  int result = _olm_clear_pk_decryption_unchecked(decryption);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_clear_pk_decryption_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption),
    int Function(Pointer<NativeType> decryption)>('olm_clear_pk_decryption');

final olm_pk_private_key_length =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_private_key_length');

final olm_pk_generate_key_random_length =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_generate_key_random_length');

int olm_pk_key_from_private(
    Pointer<NativeType> decryption,
    Pointer<Uint8> pubkey,
    int pubkey_length,
    Pointer<Uint8> privkey,
    int privkey_length) {
  int result = _olm_pk_key_from_private_unchecked(
      decryption, pubkey, pubkey_length, privkey, privkey_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pk_key_from_private_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption, Pointer<Uint8> pubkey,
        IntPtr pubkey_length, Pointer<Uint8> privkey, IntPtr privkey_length),
    int Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> pubkey,
        int pubkey_length,
        Pointer<Uint8> privkey,
        int privkey_length)>('olm_pk_key_from_private');

int olm_pk_generate_key(Pointer<NativeType> decryption, Pointer<Uint8> pubkey,
    int pubkey_length, Pointer<Uint8> privkey, int privkey_length) {
  int result = _olm_pk_generate_key_unchecked(
      decryption, pubkey, pubkey_length, privkey, privkey_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pk_generate_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption, Pointer<Uint8> pubkey,
        IntPtr pubkey_length, Pointer<Uint8> privkey, IntPtr privkey_length),
    int Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> pubkey,
        int pubkey_length,
        Pointer<Uint8> privkey,
        int privkey_length)>('olm_pk_generate_key');

int olm_pickle_pk_decryption_length(Pointer<NativeType> decryption) {
  int result = _olm_pickle_pk_decryption_length_unchecked(decryption);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pickle_pk_decryption_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption),
    int Function(
        Pointer<NativeType> decryption)>('olm_pickle_pk_decryption_length');

int olm_pickle_pk_decryption(Pointer<NativeType> decryption, Pointer<Uint8> key,
    int key_length, Pointer<Uint8> pickled, int pickled_length) {
  int result = _olm_pickle_pk_decryption_unchecked(
      decryption, key, key_length, pickled, pickled_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pickle_pk_decryption_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption, Pointer<Uint8> key,
        IntPtr key_length, Pointer<Uint8> pickled, IntPtr pickled_length),
    int Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length)>('olm_pickle_pk_decryption');

int olm_unpickle_pk_decryption(
    Pointer<NativeType> decryption,
    Pointer<Uint8> key,
    int key_length,
    Pointer<Uint8> pickled,
    int pickled_length,
    Pointer<Uint8> pubkey,
    int pubkey_length) {
  int result = _olm_unpickle_pk_decryption_unchecked(decryption, key,
      key_length, pickled, pickled_length, pubkey, pubkey_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_unpickle_pk_decryption_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> key,
        IntPtr key_length,
        Pointer<Uint8> pickled,
        IntPtr pickled_length,
        Pointer<Uint8> pubkey,
        IntPtr pubkey_length),
    int Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> key,
        int key_length,
        Pointer<Uint8> pickled,
        int pickled_length,
        Pointer<Uint8> pubkey,
        int pubkey_length)>('olm_unpickle_pk_decryption');

int olm_pk_max_plaintext_length(
    Pointer<NativeType> decryption, int ciphertext_length) {
  int result =
      _olm_pk_max_plaintext_length_unchecked(decryption, ciphertext_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pk_max_plaintext_length_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption, IntPtr ciphertext_length),
    int Function(Pointer<NativeType> decryption,
        int ciphertext_length)>('olm_pk_max_plaintext_length');

int olm_pk_decrypt(
    Pointer<NativeType> decryption,
    Pointer<Uint8> ephemeral_key,
    int ephemeral_key_length,
    Pointer<Uint8> mac,
    int mac_length,
    Pointer<Uint8> ciphertext,
    int ciphertext_length,
    Pointer<Uint8> plaintext,
    int max_plaintext_length) {
  int result = _olm_pk_decrypt_unchecked(
      decryption,
      ephemeral_key,
      ephemeral_key_length,
      mac,
      mac_length,
      ciphertext,
      ciphertext_length,
      plaintext,
      max_plaintext_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pk_decrypt_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> ephemeral_key,
        IntPtr ephemeral_key_length,
        Pointer<Uint8> mac,
        IntPtr mac_length,
        Pointer<Uint8> ciphertext,
        IntPtr ciphertext_length,
        Pointer<Uint8> plaintext,
        IntPtr max_plaintext_length),
    int Function(
        Pointer<NativeType> decryption,
        Pointer<Uint8> ephemeral_key,
        int ephemeral_key_length,
        Pointer<Uint8> mac,
        int mac_length,
        Pointer<Uint8> ciphertext,
        int ciphertext_length,
        Pointer<Uint8> plaintext,
        int max_plaintext_length)>('olm_pk_decrypt');

int olm_pk_get_private_key(Pointer<NativeType> decryption,
    Pointer<Uint8> private_key, int private_key_length) {
  int result = _olm_pk_get_private_key_unchecked(
      decryption, private_key, private_key_length);
  if (result == olm_error())
    throw_olm(olm_pk_decryption_last_error(decryption));
  return result;
}

final _olm_pk_get_private_key_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> decryption, Pointer<Uint8> private_key,
        IntPtr private_key_length),
    int Function(Pointer<NativeType> decryption, Pointer<Uint8> private_key,
        int private_key_length)>('olm_pk_get_private_key');

final olm_pk_signing_size = libolm
    .lookupFunction<IntPtr Function(), int Function()>('olm_pk_signing_size');

final olm_pk_signing = libolm.lookupFunction<
    Pointer<NativeType> Function(Pointer<Uint8> memory),
    Pointer<NativeType> Function(Pointer<Uint8> memory)>('olm_pk_signing');

final olm_pk_signing_last_error = libolm.lookupFunction<
    Pointer<Utf8> Function(Pointer<NativeType> sign),
    Pointer<Utf8> Function(
        Pointer<NativeType> sign)>('olm_pk_signing_last_error');

int olm_clear_pk_signing(Pointer<NativeType> sign) {
  int result = _olm_clear_pk_signing_unchecked(sign);
  if (result == olm_error()) throw_olm(olm_pk_signing_last_error(sign));
  return result;
}

final _olm_clear_pk_signing_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sign),
    int Function(Pointer<NativeType> sign)>('olm_clear_pk_signing');

int olm_pk_signing_key_from_seed(
    Pointer<NativeType> sign,
    Pointer<Uint8> pubkey,
    int pubkey_length,
    Pointer<Uint8> seed,
    int seed_length) {
  int result = _olm_pk_signing_key_from_seed_unchecked(
      sign, pubkey, pubkey_length, seed, seed_length);
  if (result == olm_error()) throw_olm(olm_pk_signing_last_error(sign));
  return result;
}

final _olm_pk_signing_key_from_seed_unchecked = libolm.lookupFunction<
    IntPtr Function(Pointer<NativeType> sign, Pointer<Uint8> pubkey,
        IntPtr pubkey_length, Pointer<Uint8> seed, IntPtr seed_length),
    int Function(
        Pointer<NativeType> sign,
        Pointer<Uint8> pubkey,
        int pubkey_length,
        Pointer<Uint8> seed,
        int seed_length)>('olm_pk_signing_key_from_seed');

final olm_pk_signing_seed_length =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_signing_seed_length');

final olm_pk_signing_public_key_length =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_signing_public_key_length');

final olm_pk_signature_length =
    libolm.lookupFunction<IntPtr Function(), int Function()>(
        'olm_pk_signature_length');

int olm_pk_sign(Pointer<NativeType> sign, Pointer<Uint8> message,
    int message_length, Pointer<Uint8> signature, int signature_length) {
  int result = _olm_pk_sign_unchecked(
      sign, message, message_length, signature, signature_length);
  if (result == olm_error()) throw_olm(olm_pk_signing_last_error(sign));
  return result;
}

final _olm_pk_sign_unchecked = libolm.lookupFunction<
    IntPtr Function(
        Pointer<NativeType> sign,
        Pointer<Uint8> message,
        IntPtr message_length,
        Pointer<Uint8> signature,
        IntPtr signature_length),
    int Function(
        Pointer<NativeType> sign,
        Pointer<Uint8> message,
        int message_length,
        Pointer<Uint8> signature,
        int signature_length)>('olm_pk_sign');
