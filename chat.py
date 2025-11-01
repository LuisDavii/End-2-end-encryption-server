import asyncio
import json
from db import Database

async def broadcast_user_list(online_clients):
    
    if not online_clients:
        return

    print("[Broadcast] Enviando lista de usuários atualizada...")
    all_users = []
    
    with Database() as db:
        if db:
            rows = db.fetch_all("SELECT userName FROM usuarios;")
            all_users = [row['userName'] for row in rows]
    
        # online ou offline
    user_status_list = [
        {
            "username": user,
            "isOnline": user in online_clients,
        } for user in all_users
    ]
    
    message = {"type": "user_list_update", "users": user_status_list}
    
    # Envia a mensagem para todos
    await asyncio.gather(
        *[client.send(json.dumps(message)) for client in online_clients.values()]
    )

async def handle_chat_session(websocket, username, online_clients):
    print(f"[Chat] Iniciando sessão de chat para '{username}'.")
    async for message in websocket:
        chat_data = json.loads(message)
        command = chat_data.get("type")

        if command == "REQUEST_USER_LIST":
            await broadcast_user_list(online_clients)
        
            # manda mensagens de chat
        elif command == "chat_message":
            recipient = chat_data.get("to")
            content = chat_data.get("content")
            
            chat_message = {
                "type": "chat_message",
                "from": username,
                "content": chat_data.get("content")
            }

             # Se o destinatário estiver online, envia a mensagem diretamente
            if recipient in online_clients:
                chat_message = {"type": "chat_message", "from": username, "content": content}
                await online_clients[recipient].send(json.dumps(chat_message))
                print(f"[Chat] Mensagem de '{username}' para '{recipient}' (Online).")

             # Se o destinatário estiver offline, guarda a mensagem no banco de dados
            else:
                with Database() as db:
                    if db:
                        query = "INSERT INTO mensagens_offline (remetente_username, destinatario_username, conteudo) VALUES (%s, %s, %s);"
                        db.execute_query(query, (username, recipient, content))
                        print(f"[Chat] Mensagem de '{username}' para '{recipient}' (Offline, guardada).")
                        # Notifica todos os clientes que a lista de mensagens não lidas foi atualizada
                        await broadcast_user_list(online_clients)
            

        # ADIÇÃO: Lógica para o indicador "digitando..."
        elif command in ["START_TYPING", "STOP_TYPING"]:
            recipient = chat_data.get("to")
            
            typing_status_message = {
                "type": "TYPING_STATUS_UPDATE",
                "from": username,
                "isTyping": command == "START_TYPING" 
            }
            

            if recipient in online_clients:
                await online_clients[recipient].send(json.dumps(typing_status_message))
                print(f"[Typing] Status de '{username}' para '{recipient}'.")

        elif command == "REQUEST_OFFLINE_MESSAGES":
            print(f"[*] Recebido pedido de mensagens offline de '{username}'.")
            with Database() as db:
                if db:
                    pending_messages = db.fetch_all("SELECT * FROM mensagens_offline WHERE destinatario_username = %s;", (username,))
                    
                    if pending_messages:
                        for msg in pending_messages:
                            chat_message = {"type": "chat_message", "from": msg['remetente_username'], "content": msg['conteudo']}
                            await websocket.send(json.dumps(chat_message))
                        
                        db.execute_query("DELETE FROM mensagens_offline WHERE destinatario_username = %s;", (username,))
                        print(f"[*] Mensagens offline para '{username}' enviadas e apagadas.")
                        