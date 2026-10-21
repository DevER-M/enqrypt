import secrets
from dataclasses import dataclass
from typing import Optional
from mlkem.ml_kem import ML_KEM, ML_KEM_768


@dataclass
class Recipient:
    name: str
    encaps_key: bytes
    

class ChatApp:
    """
    Simple prototype for quantum-resistant chat encryption using MLKEM.
    """
    
    def __init__(self, user_name: str):
        self.user_name = user_name
        self.kem = ML_KEM(ML_KEM_768)
        self.encaps_key, self.decaps_key = self.kem.key_gen()
        self.recipients: dict[str, Recipient] = {}
        self.session_keys: dict[str, bytes] = {}
    
    def add_recipient(self, name: str, encaps_key: bytes) -> None:
        """Add a recipient with their encapsulation key."""
        if len(encaps_key) != 1184:
            raise ValueError(f"Invalid encapsulation key size: {len(encaps_key)}")
        self.recipients[name] = Recipient(name=name, encaps_key=encaps_key)
    
    def encrypt_message(self, message: str, to: str) -> tuple[bytes, bytes]:
        """
        Encrypt a message for a recipient.
        Returns (ciphertext, session_key_used_for_symmetric_encryption).
        """
        if to not in self.recipients:
            raise ValueError(f"Unknown recipient: {to}")
        
        recipient = self.recipients[to]
        session_key, ciphertext = self.kem.encaps(recipient.encaps_key)
        
        self.session_keys[to] = session_key
        
        encrypted_msg = self._xor_encrypt(message.encode(), session_key)
        
        return ciphertext, encrypted_msg
    
    def decrypt_message(self, ciphertext: bytes, encrypted_msg: bytes, from_user: str) -> Optional[str]:
        """
        Decrypt a message from a sender.
        Returns decrypted message or None if decryption fails.
        """
        session_key = self.kem.decaps(self.decaps_key, ciphertext)
        return self._xor_decrypt(encrypted_msg, session_key).decode()
    
    def verify_shared_key(self, ciphertext: bytes, expected_key: bytes) -> bool:
        """Verify that a ciphertext decrypts to the expected shared key."""
        recovered = self.kem.decaps(self.decaps_key, ciphertext)
        return secrets.compare_digest(recovered, expected_key)
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        result = bytearray(len(data))
        key_len = len(key)
        for i, byte in enumerate(data):
            result[i] = byte ^ key[i % key_len]
        return bytes(result)
    
    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        return self._xor_encrypt(data, key)


def demo():
    """Demonstrate the chat app prototype."""
    print("=== MLKEM Quantum-Resistant Chat Demo ===\n")
    
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    print(f"Alice's encapsulation key: {len(alice.encaps_key)} bytes")
    print(f"Alice's decapsulation key: {len(alice.decaps_key)} bytes\n")
    
    alice.add_recipient("Bob", bob.encaps_key)
    bob.add_recipient("Alice", alice.encaps_key)
    
    print("Alice sending 'Hello Bob!' to Bob:")
    ciphertext, encrypted = alice.encrypt_message("Hello Bob!", "Bob")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  Encrypted message: {encrypted.hex()[:40]}...")
    
    decrypted = bob.decrypt_message(ciphertext, encrypted, "Alice")
    print(f"  Decrypted: {decrypted}\n")
    
    print("Bob sending 'Hi Alice!' to Alice:")
    ciphertext, encrypted = bob.encrypt_message("Hi Alice!", "Alice")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    
    decrypted = alice.decrypt_message(ciphertext, encrypted, "Bob")
    print(f"  Decrypted: {decrypted}\n")
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    demo()