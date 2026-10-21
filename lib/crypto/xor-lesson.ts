/*
 * TEACHING ONLY — NOT IMPORTED BY THE APPLICATION.
 *
 * The original enqrypt prototype used XOR as a stand-in for encryption:
 *
 *   def xor_for_each_byte(data: bytes, key: bytes):
 *       result = bytearray(len(data))
 *       for i, byte in enumerate(data):
 *           result[i] = byte ^ key[i % len(key)]
 *       return bytes(result)
 *
 * Why it was removed from the live path:
 *
 * - XOR is malleable. An attacker who knows any part of the plaintext can
 *   flip the corresponding ciphertext bit and flip that plaintext bit.
 * - XOR with a repeated key leaks structure and is trivially breakable when
 *   the plaintext has low entropy.
 * - It provides no integrity/authentication, so ciphertext tampering is
 *   undetectable.
 * - Reusing the same keystream across messages leaks the XOR of plaintexts.
 *
 * The live pipeline is:
 *
 *   ML-KEM-768 encapsulate -> shared secret
 *     -> HKDF-SHA256(salt = SHA-256(conversation_id), info = direction)
 *     -> two independent AES-256-GCM keys (A->B and B->A)
 *     -> AES-256-GCM(plaintext, random 96-bit nonce, AAD = conversation|sender|sequence)
 *
 * AES-GCM authenticates the ciphertext and the AAD; a modified ciphertext,
 * nonce, sender, conversation, or sequence makes decryption fail closed.
 */
export {};
