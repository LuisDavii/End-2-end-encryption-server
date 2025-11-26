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
    
    # Cria a lista de status
    user_status_list = [
        {
            "username": user,
            "isOnline": user in client_sessions,
        } for user in all_users
    ]
    
    message = {"type": "user_list_update", "users": user_status_list}
    
    # Envia a mensagem para todos usando o método .send() do SecureChannel
    # O .send() já trata a conversão para JSON e encriptação
    if client_sessions:
        await asyncio.gather(
            *[client.send(message) for client in client_sessions.values()]
        )

async def handle_chat_session(secure_channel, username, online_clients):
    print(f"[Chat] Iniciando sessão de chat para '{username}'.")
    
    try:
        while True:
            # 1. Espera e descriptografa a próxima mensagem
            # Nota: recv_and_decrypt já retorna um Dicionário (json.loads já foi feito lá dentro)
            chat_data = await secure_channel.recv_and_decrypt()
            
            command = chat_data.get("type")

            if command == "REQUEST_USER_LIST":
                await broadcast_user_list(online_clients)
            
            # Manda mensagens de chat
            elif command == "chat_message":
                recipient = chat_data.get("to")
                content = chat_data.get("content")
                
                chat_message = {
                    "type": "chat_message",
                    "from": username,
                    "content": content
                }

                # Se o destinatário estiver online, envia a mensagem diretamente
                if recipient in online_clients:
                    await online_clients[recipient].send(chat_message)
                    print(f"[Chat] Mensagem de '{username}' para '{recipient}' (Online).")

                # Se o destinatário estiver offline, guarda a mensagem no banco de dados
                else:
                    with Database() as db:
                        if db:
                            query = "INSERT INTO mensagens_offline (remetente_username, destinatario_username, conteudo) VALUES (%s, %s, %s);"
                            db.execute_query(query, (username, recipient, content))
                            print(f"[Chat] Mensagem de '{username}' para '{recipient}' (Offline, guardada).")
                            # (Opcional) Notificar que há mensagens pendentes ou atualizar lista
            

            # Lógica para o indicador "digitando..."
            elif command in ["START_TYPING", "STOP_TYPING"]:
                recipient = chat_data.get("to")
                
                typing_status_message = {
                    "type": "TYPING_STATUS_UPDATE",
                    "from": username,
                    "isTyping": command == "START_TYPING" 
                }

                if recipient in online_clients:
                    await online_clients[recipient].send(typing_status_message)
                    print(f"[Typing] Status de '{username}' para '{recipient}'.")

            elif command == "REQUEST_OFFLINE_MESSAGES":
                print(f"[*] Recebido pedido de mensagens offline de '{username}'.")
                with Database() as db:
                    if db:
                        pending_messages = db.fetch_all("SELECT * FROM mensagens_offline WHERE destinatario_username = %s;", (username,))
                        
                        if pending_messages:
                            for msg in pending_messages:
                                chat_message = {
                                    "type": "chat_message", 
                                    "from": msg['remetente_username'], 
                                    "content": msg['conteudo']
                                }
                                await secure_channel.send(chat_message)
                            
                            db.execute_query("DELETE FROM mensagens_offline WHERE destinatario_username = %s;", (username,))
                            print(f"[*] Mensagens offline para '{username}' enviadas e apagadas.")

    except Exception as e:
        # Isso acontece normalmente quando o cliente desconecta ou há erro na descriptografia
        print(f"[Chat Loop Encerrado] Usuário '{username}' desconectou ou erro: {e}")
        # A desconexão real será tratada no 'finally' do server.py
        raise e