import json
import base64
import os
import time
import random
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

KEY_MATERIAL_SIZE = 64
KEY_SIZE = 32
AES_BLOCK_SIZE = 128 

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
        
        # As duas chaves exigidas pelo PDF
        self.key1_aes = None 
        self.key2_hmac = None 
        
        self.handshake_complete = False

        self.msg_count = 0
        self.start_time = time.time()
        self.max_msgs = random.randint(50, 100) 
        self.max_time = random.randint(1800, 3600) 

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
        self.key2_hmac = key_material[KEY_SIZE:]   
        
        print(f"[Canal Seguro] Chaves AES-CBC + HMAC derivadas para {self.websocket.remote_address}")

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
        await self.encrypt_and_send(data)

    async def encrypt_and_send(self, data, is_internal_control=False):
        """Encripta usando AES-CBC e assina com HMAC (Requisito do PDF)"""
        if not self.handshake_complete:
            raise Exception("Canal seguro não estabelecido.")

        if not is_internal_control and self.should_renew():
            print("[Renovação] Condições de renovação atendidas. Iniciando renegociação...")
            await self.start_renegotiation()
            self.msg_count = 0
            self.start_time = time.time()
            self.max_msgs = random.randint(50, 100)
            self.max_time = random.randint(1800, 3600)

        if isinstance(data, str):
            plaintext = data.encode('utf-8')
        else:
            plaintext = json.dumps(data).encode('utf-8')

        padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16) 
        cipher = Cipher(algorithms.AES(self.key1_aes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        h = HMAC(self.key2_hmac, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        mac = h.finalize()

        await self.websocket.send(json.dumps({
            "iv": base64.urlsafe_b64encode(iv).decode('utf-8'),
            "payload": base64.urlsafe_b64encode(ciphertext).decode('utf-8'),
            "hmac": base64.urlsafe_b64encode(mac).decode('utf-8') 
        }))

        if not is_internal_control:
            self.msg_count += 1

    async def recv_and_decrypt(self):
        """Recebe, verifica HMAC e desencripta AES-CBC"""
        if not self.handshake_complete:
            raise Exception("Canal seguro não estabelecido.")

        encrypted_package_str = await self.websocket.recv()
        encrypted_package = json.loads(encrypted_package_str)
        
        iv = _b64_decode_pad(encrypted_package['iv'])
        ciphertext = _b64_decode_pad(encrypted_package['payload'])
        received_mac = _b64_decode_pad(encrypted_package['hmac']) 

        try:

            h = HMAC(self.key2_hmac, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            h.verify(received_mac) 

            cipher = Cipher(algorithms.AES(self.key1_aes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
            plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

            plaintext = json.loads(plaintext_bytes.decode('utf-8'))

            if plaintext.get("type") == "RENEGOTIATE_RESPONSE":
                print("[Renovação] Recebida chave pública do cliente.")
                client_pub_b64 = plaintext.get("public_key")
                client_pub_bytes = _b64_decode_pad(client_pub_b64)
                
                new_client_pub_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
                
                new_shared_secret = self.temp_private_key.exchange(new_client_pub_key)
                
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=KEY_MATERIAL_SIZE,
                    salt=self.temp_salt,
                    info=b'handshake_info',
                    backend=default_backend()
                )
                key_material = hkdf.derive(new_shared_secret)
                
                self.key1_aes = key_material[:KEY_SIZE]
                self.key2_hmac = key_material[KEY_SIZE:]
                
                self.server_private_key = self.temp_private_key
                self.server_public_key = self.temp_private_key.public_key()
                self.client_public_key = new_client_pub_key
                
                print("[Renovação] Sessão renovada com sucesso! Novas chaves aplicadas.")
                return await self.recv_and_decrypt()

            self.msg_count += 1 
            return plaintext
           
        except Exception as e:
            print(f"[PERIGO] Falha na segurança (HMAC ou Decriptação): {e}")
            raise Exception("Security check failed!")
    
    def should_renew(self):
        if not self.handshake_complete:
            return False
        elapsed_time = time.time() - self.start_time
        if self.msg_count >= self.max_msgs or elapsed_time >= self.max_time:
            return True
        return False

    async def start_renegotiation(self):
        print(f"[Renovação] Iniciando troca de chaves com {self.websocket.remote_address}...")

        new_private_key = x25519.X25519PrivateKey.generate()
        new_public_key = new_private_key.public_key()
        new_pub_bytes = new_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        new_pub_b64 = base64.urlsafe_b64encode(new_pub_bytes).decode('utf-8')

        new_salt = os.urandom(KEY_SIZE)
        new_salt_b64 = base64.urlsafe_b64encode(new_salt).decode('utf-8')

        await self.encrypt_and_send({
            "type": "RENEGOTIATE_REQUEST",
            "public_key": new_pub_b64,
            "salt": new_salt_b64
        }, is_internal_control=True) 

        self.temp_private_key = new_private_key
        self.temp_salt = new_salt

    async def close(self):
        await self.websocket.close()