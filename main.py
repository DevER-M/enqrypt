from mlkem.ml_kem import ML_KEM
#print(user_a_encap.hex(),user_a_decap.hex(),sep='\n')
#print(session_user_ab.hex(),'\n',cipher.hex())


# this function returns bytes with input of two bytes
def xor_for_each_byte(data: bytes, key: bytes):
    result = bytearray(len(data))
    key_len = len(key)
    for i, byte in enumerate(data):
        result[i] = byte ^ key[i % key_len]
    return bytes(result)


# initialize the mlkem object for each user to generate keys etc
user_a=ML_KEM()
user_a_public,user_a_private=user_a.key_gen()
user_a_key_db={}

user_b=ML_KEM()
user_b_public,user_b_private=user_b.key_gen()
user_b_key_db={}

user_a_key_db['user_b'],user_b_key_db['user_a']=user_b_public,user_a_public # transfer of info (happens in chat app through internet)

session_user_ab,cipher=user_a.encaps(user_a_key_db['user_b']) # user_a encapsulates user_b's public key and generates a session key and a cipher text
# session user ab is the symmentric key used to encrypt the text, while cipher acts as a relation for the end user to create the symmentric key

encrypted_msg=xor_for_each_byte("Hi".encode(),session_user_ab)  # now user_a encrypts the message to send using the session key
print(encrypted_msg)
# now user a sends the encrypted message and cipher text to user b

# user_b derives the sessionkey using user_b's private key and cipher text sent by user_a
session_user_ba=user_b.decaps(user_b_private,cipher)
print('Session key created using both the users public keys + random data equals to session key \
      created using user_bs private key and transferred cipher text',session_user_ab==session_user_ba)
decrypted_msg=xor_for_each_byte(encrypted_msg,session_user_ba)

print('decrypted message: ',decrypted_msg.decode())