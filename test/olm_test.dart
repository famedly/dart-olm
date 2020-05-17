// Copyright (c) 2020 Famedly GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:olm/olm.dart' as olm;
import 'package:test/test.dart';
import 'dart:convert';

void main() async {
  const test_message = "Hello, World!";
  const test_key = "Test";

  await olm.init();

  test("get library version", () {
    expect(olm.get_library_version(), allOf(isList, hasLength(3)));
  });

  test("pickle/unpickle an account", () {
    olm.Account account = olm.Account();
    account.create();
    account.generate_one_time_keys(1);
    final id_key1 = account.identity_keys();
    final ot_key1 = account.one_time_keys();
    final data = account.pickle(test_key);
    account.free();
    olm.Account account2 = olm.Account();
    account2.unpickle(test_key, data);
    final id_key2 = account2.identity_keys();
    final ot_key2 = account2.one_time_keys();
    expect(id_key1, id_key2);
    expect(ot_key1, ot_key2);
    account2.mark_keys_as_published();
    expect(account2.max_number_of_one_time_keys(), isPositive);
    account2.free();
  });

  test("send a message", () {
    final alice = olm.Account();
    final bob = olm.Account();
    alice.create();
    bob.create();
    bob.generate_one_time_keys(1);
    final bob_id_key = json.decode(bob.identity_keys())['curve25519'];
    final bob_ot_key = json.decode(bob.one_time_keys())['curve25519']['AAAAAQ'];
    final alice_s = olm.Session();
    alice_s.create_outbound(alice, bob_id_key, bob_ot_key);
    final alice_message = alice_s.encrypt(test_message);
    final bob_s = olm.Session();
    bob_s.create_inbound(bob, alice_message.body);
    expect(bob_s.has_received_message(), false);
    final result = bob_s.decrypt(alice_message.type, alice_message.body);
    bob.remove_one_time_keys(bob_s);
    expect(bob_s.session_id(), allOf(isA<String>(), isNotEmpty));
    expect(bob_s.has_received_message(), true);

    for(var i = 0; i < 100; i++) {
      final alice_message = alice_s.encrypt(test_message);
      final bob_result = bob_s.decrypt(alice_message.type, alice_message.body);
      expect(bob_result, test_message);
      final bob_message = bob_s.encrypt(test_message);
      final alice_result = alice_s.decrypt(bob_message.type, bob_message.body);
      expect(alice_result, test_message);
    }

    bob_s.free();
    alice_s.free();
    bob.free();
    alice.free();

    expect(result, test_message);
  });

  test("send a message with pickle/unpickle", () {
    final alice = olm.Account();
    final bob = olm.Account();
    alice.create();
    bob.create();
    bob.generate_one_time_keys(1);
    final bob_id_key = json.decode(bob.identity_keys())['curve25519'];
    final bob_ot_key = json.decode(bob.one_time_keys())['curve25519']['AAAAAQ'];
    final alice_s = olm.Session();
    alice_s.create_outbound(alice, bob_id_key, bob_ot_key);

    final alice_data = alice.pickle(test_key);
    final alice_s_data = alice_s.pickle(test_key);
    final bob_data = bob.pickle(test_key);
    alice_s.free();
    bob.free();
    alice.free();

    final alice2 = olm.Account();
    alice2.unpickle(test_key, alice_data);
    final alice_s2 = olm.Session();
    alice_s2.unpickle(test_key, alice_s_data);
    final bob2 = olm.Account();
    bob2.unpickle(test_key, bob_data);

    final alice_message = alice_s2.encrypt(test_message);
    final bob_s = olm.Session();
    bob_s.create_inbound(bob2, alice_message.body);
    final result = bob_s.decrypt(alice_message.type, alice_message.body);
    bob2.remove_one_time_keys(bob_s);
    bob2.free();
    alice_s2.free();
    alice2.free();

    expect(result, test_message);
  });

  test("send a group message", () {
    final outbound_session = olm.OutboundGroupSession();
    outbound_session.create();
    expect(outbound_session.session_id(), allOf(isA<String>(), isNotEmpty));
    final session_key = outbound_session.session_key();
    expect(outbound_session.message_index(), 0);
    final inbound_session = olm.InboundGroupSession();
    inbound_session.create(session_key);
    final ciphertext = outbound_session.encrypt(test_message);
    final decrypted = inbound_session.decrypt(ciphertext);

    expect(inbound_session.session_id(), allOf(isA<String>(), isNotEmpty));
    expect(inbound_session.first_known_index(), 0);
    expect(inbound_session.export_session(0), allOf(isA<String>(), isNotEmpty));

    outbound_session.free();
    inbound_session.free();

    expect(decrypted.plaintext, test_message);
  });

  test("send a group message with pickle/unpickle", () {
    final outbound_session = olm.OutboundGroupSession();
    outbound_session.create();
    final session_id = outbound_session.session_id();
    final session_key = outbound_session.session_key();
    final message_index = outbound_session.message_index();
    final inbound_session = olm.InboundGroupSession();
    inbound_session.create(session_key);

    final outbound_session_data = outbound_session.pickle(test_key);
    final inbound_session_data = inbound_session.pickle(test_key);
    inbound_session.free();
    outbound_session.free();

    final outbound_session2 = olm.OutboundGroupSession();
    outbound_session2.unpickle(test_key, outbound_session_data);
    expect(outbound_session2.session_id(), session_id);
    expect(outbound_session2.message_index(), message_index);
    final ciphertext = outbound_session2.encrypt(test_message);
    final inbound_session2 = olm.InboundGroupSession();
    inbound_session2.unpickle(test_key, inbound_session_data);
    final decrypted = inbound_session2.decrypt(ciphertext);

    inbound_session2.free();
    outbound_session2.free();

    expect(decrypted.plaintext, test_message);
  });

  test("utility", () {
    final utility = olm.Utility();
    final hash = utility.sha256("Hello");
    utility.free();

    expect(hash, "GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk");
  });

  test("sign verify good", () {
    final account = olm.Account();
    account.create();
    final signature = account.sign(test_message);
    final id_key = json.decode(account.identity_keys())['ed25519'];
    account.free();

    final utility = olm.Utility();
    utility.ed25519_verify(id_key, test_message, signature);
    utility.free();
  });

  test("sign verify bad", () {
    final account = olm.Account();
    account.create();
    final signature = account.sign(test_message);
    account.create();
    final id_key = json.decode(account.identity_keys())['ed25519'];
    account.free();

    final utility = olm.Utility();
    expect(() => utility.ed25519_verify(id_key, test_message, signature), throwsA(anything));
  });

  test("invalid method calls", () {
    expect(() => olm.Account().unpickle(test_key, ""), throwsA(anything));
    expect(() => olm.Session().unpickle(test_key, ""), throwsA(anything));
    expect(() => olm.InboundGroupSession().unpickle(test_key, ""), throwsA(anything));
    expect(() => olm.OutboundGroupSession().unpickle(test_key, ""), throwsA(anything));
    expect(() => olm.Session().create_inbound_from(olm.Account(), "", ""), throwsA(anything));
    expect(olm.Session().matches_inbound(""), false);
    expect(() => olm.Session().matches_inbound_from("", ""), throwsA(anything));
    expect(() => olm.InboundGroupSession().import_session(""), throwsA(anything));
  });

  test("send multiple messages, one direction", () async {
    final alice = olm.Account();
    final bob = olm.Account();
    alice.create();
    bob.create();
    bob.generate_one_time_keys(1);
    final bob_id_key = json.decode(bob.identity_keys())['curve25519'];
    final bob_ot_key = json.decode(bob.one_time_keys())['curve25519']['AAAAAQ'];
    final alice_s = olm.Session();
    alice_s.create_outbound(alice, bob_id_key, bob_ot_key);
    final alice_message_first = alice_s.encrypt(test_message);
    final bob_s = olm.Session();
    bob_s.create_inbound_from(bob, json.decode(alice.identity_keys())['curve25519'], alice_message_first.body);
    final alice_decrypted_first = bob_s.decrypt(alice_message_first.type, alice_message_first.body);
    expect(alice_decrypted_first, test_message);
    bob.remove_one_time_keys(bob_s);

    for (int i = 0; i < 10; i++) {
      final alice_plain = "Alice $i";
      try {
        final alice_message = alice_s.encrypt(alice_plain);
        final alice_decrypted = bob_s.decrypt(alice_message.type, alice_message.body);
        expect(alice_decrypted, alice_plain);
      } catch (e) {
        print("Exception in round $i");
        rethrow;
      }
    }

    bob_s.free();
    alice_s.free();
    bob.free();
    alice.free();
  });

  test("send multiple messages, round trip", () async {
    final alice = olm.Account();
    final bob = olm.Account();
    alice.create();
    bob.create();
    bob.generate_one_time_keys(1);
    final bob_id_key = json.decode(bob.identity_keys())['curve25519'];
    final bob_ot_key = json.decode(bob.one_time_keys())['curve25519']['AAAAAQ'];
    final alice_s = olm.Session();
    alice_s.create_outbound(alice, bob_id_key, bob_ot_key);
    final alice_message_first = alice_s.encrypt(test_message);
    final bob_s = olm.Session();
    bob_s.create_inbound_from(bob, json.decode(alice.identity_keys())['curve25519'], alice_message_first.body);
    final alice_decrypted_first = bob_s.decrypt(alice_message_first.type, alice_message_first.body);
    expect(alice_decrypted_first, test_message);
    bob.remove_one_time_keys(bob_s);

    for (int i = 0; i < 10; i++) {
      final alice_plain = "Alice $i";
      final bob_plain = "Bob $i";
      try {
        final alice_message = alice_s.encrypt(alice_plain);
        final alice_decrypted = bob_s.decrypt(alice_message.type, alice_message.body);
        expect(alice_decrypted, alice_plain);
        final bob_message = bob_s.encrypt(bob_plain);
        final bob_decrypted = alice_s.decrypt(bob_message.type, bob_message.body);
        expect(bob_decrypted, bob_plain);
      } catch (e) {
        print("Exception in round $i");
        rethrow;
      }
    }

    bob_s.free();
    alice_s.free();
    bob.free();
    alice.free();
  });
}
