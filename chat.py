import asyncio
import json
from db import Database

async def broadcast_user_list(client_sessions):
    if not client_sessions:
        return

    print("[Broadcast] Enviando lista de usuários atualizada...")
    all_users = []
    
    with Database() as db:
        if db:
            rows = db.fetch_all("SELECT userName FROM usuarios;")
            all_users = [row['userName'] for row in rows]
    
    user_status_list = [
        {
            "username": user,
            "isOnline": user in client_sessions,
        } for user in all_users
    ]
    
    message = {"type": "user_list_update", "users": user_status_list}

    if client_sessions:
        await asyncio.gather(
            *[client.send(message) for client in client_sessions.values()]
        )


async def handle_chat_session(secure_channel, username, online_clients):
    print(f"[Chat] Iniciando sessão de chat para '{username}'.")
    
    try:
        while True:
            chat_data = await secure_channel.recv_and_decrypt()
            command = chat_data.get("type")

            if command in ["E2E_HANDSHAKE", "E2E_AUTH", "E2E_MSG"]:
                target_user = chat_data.get("to")
                payload = chat_data.get("payload")
                
                if target_user in online_clients:
                    await online_clients[target_user].send({
                        "type": command,
                        "from": username,
                        "payload": payload
                    })
                    print(f"[Roteamento] {command} de {username} para {target_user}")
                
                elif command == "E2E_MSG":
                    with Database() as db:
                        if db:
                            query = "INSERT INTO mensagens_offline (remetente_username, destinatario_username, conteudo) VALUES (%s, %s, %s);"
                            db.execute_query(query, (username, target_user, json.dumps(payload)))
                            print(f"[Offline] Mensagem E2EE guardada para {target_user}")

            elif command == "GET_PUBLIC_KEY":
                target_user = chat_data.get("target_username")
                with Database() as db:
                    if db:
                        rows = db.fetch_all("SELECT public_key FROM usuarios WHERE userName = %s;", (target_user,))
                        if rows:
                            pub_key = rows[0]['public_key']
                            await secure_channel.send({
                                "type": "PUBLIC_KEY_RESPONSE",
                                "username": target_user,
                                "public_key": pub_key
                            })
                        else:
                             await secure_channel.send({"type": "ERROR", "message": "User not found"})

            elif command == "REQUEST_USER_LIST":
                await broadcast_user_list(online_clients)

            elif command == "REQUEST_OFFLINE_MESSAGES":
                with Database() as db:
                    if db:
                        msgs = db.fetch_all("SELECT * FROM mensagens_offline WHERE destinatario_username = %s;", (username,))
                        for msg in msgs:
                            content_json = json.loads(msg['conteudo'])
                            await secure_channel.send({
                                "type": "E2E_MSG", 
                                "from": msg['remetente_username'], 
                                "payload": content_json
                            })
                        db.execute_query("DELETE FROM mensagens_offline WHERE destinatario_username = %s;", (username,))

            elif command in ["START_TYPING", "STOP_TYPING"]:
                recipient = chat_data.get("to")
                if recipient in online_clients:
                    await online_clients[recipient].send({
                        "type": "TYPING_STATUS_UPDATE",
                        "from": username,
                        "isTyping": command == "START_TYPING"
                    })

    except Exception as e:
        print(f"[Chat] Erro/Desconexão de {username}: {e}")
        raise e