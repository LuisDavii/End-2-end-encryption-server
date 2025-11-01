import json
from db import Database
from argon2 import PasswordHasher 
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

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


async def handle_login(data, websocket, online_clients):
    username = data.get("username")
    plain_password = data.get("password")

    with Database() as db:
        if not db:
            await websocket.send(json.dumps({"type": "auth_response", "status": "SERVER_ERROR"}))
            return None

        query = "SELECT senha FROM usuarios WHERE userName = %s;"
        result = db.fetch_all(query, (username,))
        
        if result:
            stored_hash = result[0]['senha']
            try:
                ph.verify(stored_hash, plain_password)
                
                online_clients[username] = websocket
                await websocket.send(json.dumps({"type": "auth_response", "status": "LOGIN_SUCCESS"}))
                return username
            
            #senha incorreta
            except VerifyMismatchError:
                await websocket.send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
                return None
            
            #outro erro qualquer
            except Exception as e:
                print(f"[Erro de Verificação] {e}")
                await websocket.send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
                return None
        else:
            await websocket.send(json.dumps({"type": "auth_response", "status": "LOGIN_FAILED"}))
            return None 