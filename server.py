import asyncio
import json
import websockets

from auth import handle_login, handle_register
from chat import handle_chat_session, broadcast_user_list
from secure_channel import SecureChannel

CLIENT_SESSIONS = {}

async def handler(websocket, path):

    channel = SecureChannel(websocket)
    current_user = None

    try:
            first_message = await websocket.recv()
            handshake_data = json.loads(first_message)
            
            if handshake_data.get("type") == "HANDSHAKE_START":
                handshake_ok = await channel.handle_handshake(handshake_data)
                if not handshake_ok:
                    return 
            else:
                print("[Erro] Conexão fechada. Primeira mensagem não foi o handshake.")
                return

            auth_message = await channel.recv_and_decrypt()
            command = auth_message.get("type")

            if command == "REGISTER":
                await handle_register(auth_message, channel) 
            elif command == "LOGIN":
                current_user = await handle_login(auth_message, channel, CLIENT_SESSIONS)
                if current_user:
                    print(f"[Conexão] Usuário '{current_user}' autenticado e online.")

                    CLIENT_SESSIONS[current_user] = channel
                    await broadcast_user_list(CLIENT_SESSIONS) 

            if current_user:
                await handle_chat_session(channel, current_user, CLIENT_SESSIONS)

    except Exception as e:
        print(f"[Erro no handler principal] {e}")
    finally:

        if current_user and current_user in CLIENT_SESSIONS:
            print(f"[Desconexão] Usuário '{current_user}' desconectou-se.")
            del CLIENT_SESSIONS[current_user]
            await broadcast_user_list(CLIENT_SESSIONS)

async def main():
    async with websockets.serve(handler, "localhost", 12345):
        print("[*] Servidor Principal ouvindo em localhost:12345")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())