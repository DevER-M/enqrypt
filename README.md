# enqrypt - Quantum-Resistant Chat Encryption

A prototype implementing MLKEM (Module-Lattice-based Key Encapsulation Mechanism) for quantum-resistant encryption in Python.

## Features

- Uses MLKEM-768 (NIST standard finalized in July 2022)
- CCA-secure key encapsulation
- Works with existing `mlkem` library

## Quick Start

```bash
# Install
uv pip install -e .

# Run demo
uv run python3 -m enqrypt --demo
```

## Usage

### Command Line

```bash
# Initialize a user
uv run python3 -m enqrypt --init Alice
# Output: prints encapsulation and decapsulation keys

# Send a message
uv run python3 -m enqrypt --send Bob "Hello Bob!"
```

### Python API

```python
from enqrypt.chat import ChatApp

# Create users
alice = ChatApp("Alice")
bob = ChatApp("Bob")

# Exchange keys (in real app, send encaps keys securely)
alice.add_recipient("Bob", bob.encaps_key)
bob.add_recipient("Alice", alice.encaps_key)

# Encrypt and send
ciphertext, encrypted_msg = alice.encrypt_message("Hello Bob!", "Bob")
# Send ciphertext + encrypted_msg to Bob

# Decrypt on receiver side
decrypted = bob.decrypt_message(ciphertext, encrypted_msg, "Alice")
print(decrypted)  # "Hello Bob!"
```

## Security

- Keys are 1184 bytes (encapsulation) / 2400 bytes (decapsulation)
- Shared secrets are 32 bytes
- Ciphertexts are 1088 bytes
- Resistant to quantum attacks (based on hardness of Module-LWE problem)

## API Reference

`ChatApp(user_name: str)`

- `encaps_key`: bytes - Public encapsulation key (share with others)
- `decaps_key`: bytes - Private decapsulation key (keep secret)
- `add_recipient(name: str, encaps_key: bytes)` - Add a recipient
- `encrypt_message(message: str, to: str) -> tuple[bytes, bytes]` - Encrypt
- `decrypt_message(ciphertext: bytes, encrypted_msg: bytes, from_user: str) -> Optional[str]` - Decrypt