import asyncio
import json
import websockets

from auth import handle_login, handle_register
from chat import handle_chat_session, broadcast_user_list

ONLINE_CLIENTS = {}

async def handler(websocket, path):

    current_user = None
    try:
        print("[Conexão] Novo cliente conectado.")
        auth_message = await websocket.recv()
        data = json.loads(auth_message)
        command = data.get("type")

        if command == "REGISTER":
            await handle_register(data, websocket)

        elif command == "LOGIN":
            current_user = await handle_login(data, websocket, ONLINE_CLIENTS)
            if current_user:
                print(f"[Conexão] Usuário '{current_user}' autenticado e online.")
                await broadcast_user_list(ONLINE_CLIENTS)

        if current_user:
            await handle_chat_session(websocket, current_user, ONLINE_CLIENTS)

    except Exception as e:
        print(f"[Erro no handler principal] {e}")

    finally:
        if current_user and current_user in ONLINE_CLIENTS:
            print(f"[Desconexão] Usuário '{current_user}' desconectou-se.")
    
            del ONLINE_CLIENTS[current_user]
            await broadcast_user_list(ONLINE_CLIENTS)

async def main():
    async with websockets.serve(handler, "localhost", 12345):
        print("[*] Servidor Principal ouvindo em localhost:12345")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())