from enqrypt.chat import ChatApp


def test_chat_app():
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    assert len(alice.encaps_key) == 1184
    assert len(alice.decaps_key) == 2400
    
    alice.add_recipient("Bob", bob.encaps_key)
    bob.add_recipient("Alice", alice.encaps_key)
    
    ciphertext, encrypted = alice.encrypt_message("Hello Bob!", "Bob")
    assert len(ciphertext) == 1088
    
    decrypted = bob.decrypt_message(ciphertext, encrypted, "Alice")
    assert decrypted == "Hello Bob!"
    
    ciphertext2, encrypted2 = bob.encrypt_message("Test message", "Alice")
    decrypted2 = alice.decrypt_message(ciphertext2, encrypted2, "Bob")
    assert decrypted2 == "Test message"


def test_session_key_handshake():
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    alice.add_recipient("Bob", bob.encaps_key)
    bob.add_recipient("Alice", alice.encaps_key)
    
    c1, e1 = alice.encrypt_message("Hello", "Bob")
    d1 = bob.decrypt_message(c1, e1, "Alice")
    assert d1 == "Hello"
    
    c2, e2 = bob.encrypt_message("Hi", "Alice")
    d2 = alice.decrypt_message(c2, e2, "Bob")
    assert d2 == "Hi"


def test_two_way_communication():
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    alice.add_recipient("Bob", bob.encaps_key)
    bob.add_recipient("Alice", alice.encaps_key)
    
    c1, e1 = alice.encrypt_message("Hello Bob!", "Bob")
    d1 = bob.decrypt_message(c1, e1, "Alice")
    assert d1 == "Hello Bob!"
    
    c2, e2 = bob.encrypt_message("Hi Alice!", "Alice")
    d2 = alice.decrypt_message(c2, e2, "Bob")
    assert d2 == "Hi Alice!"


def test_large_message():
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    alice.add_recipient("Bob", bob.encaps_key)
    
    large_msg = "A" * 10000
    c, e = alice.encrypt_message(large_msg, "Bob")
    d = bob.decrypt_message(c, e, "Alice")
    assert d == large_msg