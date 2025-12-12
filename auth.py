import json
import base64
import os
from db import Database
from argon2 import PasswordHasher 
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

ph = PasswordHasher()
PENDING_CHALLENGES = {}

def _b64_decode_pad(data_str):
    if isinstance(data_str, str):
        data_bytes = data_str.encode('utf-8')
    else:
        data_bytes = data_str
    missing_padding = len(data_bytes) % 4
    if missing_padding:
        data_bytes += b'=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data_bytes)

async def handle_register(data, websocket):
    username = data.get("username")
    plain_password = data.get("password")
    public_key = data.get("public_key")
    
    if not username or not plain_password or not public_key:
        await websocket.send(json.dumps({"type": "auth_response", "status": "SERVER_ERROR", "message": "Missing fields"}))
        return
    print("[Registro] Processando novo registro...")
    
    try:
        hashed_password = ph.hash(plain_password)

    except Exception as e:
        print(f"[Erro de Hashing] {e}")
        await websocket.send(json.dumps({"type": "auth_response", "status": "SERVER_ERROR", "message": "Hashing failed"}))
        return
    
    with Database() as db:
        if not db:
            await websocket.send(json.dumps({"type": "auth_response", "status": "SERVER_ERROR"}))
            return

        query_check = "SELECT userName FROM usuarios WHERE userName = %s;"
        if db.fetch_all(query_check, (username,)):
            await websocket.send(json.dumps({"type": "auth_response", "status": "REGISTER_FAILED:USERNAME_EXISTS"}))
        else:
            query_insert = "INSERT INTO usuarios (userName, senha, public_key) VALUES (%s, %s, %s);"
            db.execute_query(query_insert, (username, hashed_password,public_key))
            await websocket.send(json.dumps({"type": "auth_response", "status": "REGISTER_SUCCESS"}))


async def handle_login(data,channel ,online_clients):
    username = data.get("username")
    plain_password = data.get("password")
    new_public_key = data.get("new_public_key")

    with Database() as db:
        if not db:
            await channel.encrypt_and_send(json.dumps({"type": "auth_response", "status": "SERVER_ERROR"}))
            return None

        query = "SELECT senha FROM usuarios WHERE userName = %s;"
        result = db.fetch_all(query, (username,))
        
        if result:
            stored_hash = result[0]['senha']
            try:
                ph.verify(stored_hash, plain_password)
                if new_public_key:
                    print(f"[Auth] Atualizando chave pública para {username} (novo dispositivo)")
                    db.execute_query("UPDATE usuarios SET public_key = %s WHERE userName = %s;", (new_public_key, username))
                
                online_clients[username] = channel
                await channel.encrypt_and_send(json.dumps({"type": "auth_response", "status": "LOGIN_SUCCESS"}))
                return username
            
            #senha incorreta
            except VerifyMismatchError:
                await channel.encrypt_and_send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
                return None
            
            #outro erro qualquer
            except Exception as e:
                print(f"[Erro de Verificação] {e}")
                await channel.encrypt_and_send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
                return None
        else:
            await channel.encrypt_and_send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
            return None 
        
async def handle_challenge_request(data, channel):
    username = data.get("username")
    
    nonce = os.urandom(32)
    PENDING_CHALLENGES[username] = nonce
    
    print(f"[Auth] Desafio gerado para {username}")
    
    await channel.encrypt_and_send({
        "type": "LOGIN_CHALLENGE",
        "nonce": base64.urlsafe_b64encode(nonce).decode('utf-8')
    })

async def handle_challenge_response(data, channel, online_clients):
    username = data.get("username")
    signature_b64 = data.get("signature")
    
    if username not in PENDING_CHALLENGES:
        await channel.encrypt_and_send({"type": "auth_response", "status": "LOGIN_FAILED", "message": "No challenge pending"})
        return

    nonce = PENDING_CHALLENGES.pop(username) 
    
    with Database() as db:
        if not db: return

        rows = db.fetch_all("SELECT public_key FROM usuarios WHERE userName = %s;", (username,))
        if not rows:
            await channel.encrypt_and_send({"type": "auth_response", "status": "LOGIN_FAILED"})
            return
            
        public_key_b64 = rows[0]['public_key']
        
        try:
            public_key_bytes = _b64_decode_pad(public_key_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            signature_bytes = _b64_decode_pad(signature_b64)

            public_key.verify(signature_bytes, nonce)
            
            print(f"[Auth] Assinatura válida! Usuário {username} autenticado via desafio.")
            online_clients[username] = channel
            await channel.encrypt_and_send({"type": "auth_response", "status": "LOGIN_SUCCESS"})
            return username
            
        except InvalidSignature:
            print(f"[Auth] Assinatura inválida para {username}")
            await channel.encrypt_and_send({"type": "auth_response", "status": "LOGIN_FAILED", "message": "Invalid signature"})
        except Exception as e:
            print(f"[Auth] Erro na validação: {e}")
            await channel.encrypt_and_send({"type": "auth_response", "status": "LOGIN_FAILED"})