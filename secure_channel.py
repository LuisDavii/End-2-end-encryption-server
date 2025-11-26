# secure_channel.py

import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

KEY_MATERIAL_SIZE = 64
KEY_SIZE = 32
GCM_IV_SIZE = 12 
GCM_TAG_SIZE = 16

def _b64_decode_pad(data_str):
    if isinstance(data_str, str):
        data_bytes = data_str.encode('utf-8')
    else:
        data_bytes = data_str
        
    missing_padding = len(data_bytes) % 4
    if missing_padding:
        data_bytes += b'=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data_bytes)


class SecureChannel:
    def __init__(self, websocket):
        self.websocket = websocket
        self.server_private_key = x25519.X25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()
        
        self.client_public_key = None
        self.shared_secret = None
        self.key1_aes = None 
        self.handshake_complete = False

    def perform_key_derivation(self, salt_bytes):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_MATERIAL_SIZE, 
            salt=salt_bytes,
            info=b'handshake_info',
            backend=default_backend()
        )
        key_material = hkdf.derive(self.shared_secret)
        self.key1_aes = key_material[:KEY_SIZE] 
        print(f"[Canal Seguro] Chave AES-GCM derivada com sucesso para {self.websocket.remote_address}")

    async def handle_handshake(self, handshake_data):
        try:
            client_key_b64 = handshake_data['public_key']
            salt_b64 = handshake_data['salt']

            client_key_bytes = _b64_decode_pad(client_key_b64)
            salt_bytes = _b64_decode_pad(salt_b64)

            self.client_public_key = x25519.X25519PublicKey.from_public_bytes(client_key_bytes)
            self.shared_secret = self.server_private_key.exchange(self.client_public_key)
            self.perform_key_derivation(salt_bytes)

            server_pub_bytes = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            server_key_b64 = base64.urlsafe_b64encode(server_pub_bytes).decode('utf-8')
            
            await self.websocket.send(json.dumps({
                "type": "HANDSHAKE_RESPONSE",
                "public_key": server_key_b64
            }))
            
            self.handshake_complete = True
            print(f"[Canal Seguro] Handshake concluído com {self.websocket.remote_address}")
            return True
            
        except Exception as e:
            print(f"[Erro no Handshake] {e}")
            import traceback
            traceback.print_exc()
            return False

    async def send(self, data):
        """
        Alias para encrypt_and_send para manter compatibilidade com códigos
        que chamam .send() (como o chat.py).
        """
        await self.encrypt_and_send(data)

    async def encrypt_and_send(self, data):
        """Encripta e autentica os dados usando AES-GCM."""
        if not self.handshake_complete:
            raise Exception("Canal seguro não estabelecido.")
            
        if isinstance(data, str):
            plaintext = data.encode('utf-8')
        else:
            plaintext = json.dumps(data).encode('utf-8')
        
        iv = os.urandom(GCM_IV_SIZE) 
        
        aesgcm = AESGCM(self.key1_aes)
        encrypted_payload_with_mac = aesgcm.encrypt(iv, plaintext, None)
        
        encrypted_payload = encrypted_payload_with_mac[:-GCM_TAG_SIZE]
        mac = encrypted_payload_with_mac[-GCM_TAG_SIZE:]

        # Envia no formato que o SecureChannelWrapper do Dart espera
        await self.websocket.send(json.dumps({
            "iv": base64.urlsafe_b64encode(iv).decode('utf-8'),
            "payload": base64.urlsafe_b64encode(encrypted_payload).decode('utf-8'),
            "hmac": base64.urlsafe_b64encode(mac).decode('utf-8') 
        }))

    async def recv_and_decrypt(self):
        """Recebe, verifica (GCM) e desencripta a mensagem."""
        if not self.handshake_complete:
            raise Exception("Canal seguro não estabelecido.")

        encrypted_package_str = await self.websocket.recv()
        encrypted_package = json.loads(encrypted_package_str)
        
        iv = _b64_decode_pad(encrypted_package['iv'])
        encrypted_payload = _b64_decode_pad(encrypted_package['payload'])
        received_mac = _b64_decode_pad(encrypted_package['hmac']) 

        try:
            aesgcm = AESGCM(self.key1_aes)
            encrypted_payload_with_mac = encrypted_payload + received_mac
            
            plaintext_bytes = aesgcm.decrypt(iv, encrypted_payload_with_mac, None)

            return json.loads(plaintext_bytes.decode('utf-8'))
            
        except Exception as e:
            print(f"[PERIGO] VERIFICAÇÃO DO AES-GCM FALHOU! {e}")
            raise Exception("AES-GCM decryption failed (InvalidTag)!")
    
    async def close(self):
        await self.websocket.close()