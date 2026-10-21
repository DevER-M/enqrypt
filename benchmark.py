import time
from enqrypt.chat import ChatApp


def benchmark():
    alice = ChatApp("Alice")
    bob = ChatApp("Bob")
    
    alice.add_recipient("Bob", bob.encaps_key)
    
    # Key generation
    start = time.perf_counter()
    ek1, dk1 = alice.kem.key_gen()
    keygen_time = time.perf_counter() - start
    print(f"Key generation: {keygen_time*1000:.1f} ms")
    
    # Encapsulation
    start = time.perf_counter()
    k, c = alice.kem.encaps(bob.encaps_key)
    encaps_time = time.perf_counter() - start
    print(f"Encapsulation: {encaps_time*1000:.1f} ms")
    
    # Decapsulation
    start = time.perf_counter()
    k2 = bob.kem.decaps(bob.decaps_key, c)
    decaps_time = time.perf_counter() - start
    print(f"Decapsulation: {decaps_time*1000:.1f} ms")
    
    print(f"\nShared key matches: {k == k2}")
    print(f"\nKey sizes:")
    print(f"  Encapsulation key: {len(ek1)} bytes")
    print(f"  Decapsulation key: {len(dk1)} bytes")
    print(f"  Ciphertext: {len(c)} bytes")
    print(f"  Shared key: {len(k)} bytes")


if __name__ == "__main__":
    benchmark()