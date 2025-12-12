# Servidor de Chat Seguro (Projeto 2)

Este é o componente Back-end do projeto de Criptografia Ponta-a-Ponta. Ele é responsável por gerenciar conexões WebSocket, autenticação de usuários e roteamento de mensagens cifradas.

**Nota Importante:** Este servidor atua como um roteador "cego". Ele **não** tem acesso ao conteúdo das mensagens trocadas entre clientes (E2EE), apenas encaminha os pacotes cifrados.

## Pre-requisitos

* **Python 3.10** ou superior.
* **MySQL Server** (local ou remoto) rodando.

## Instalacao e Configuracao

Siga os passos abaixo na ordem para configurar o ambiente.

### 1. Configurar o Banco de Dados (MySQL)

Acesse o seu console do MySQL ou use uma ferramenta como Workbench/DBeaver e execute o seguinte script SQL para criar o banco e as tabelas:

```sql
CREATE DATABASE chat_seguro;
USE chat_seguro;

-- Tabela de Usuarios
-- Armazena credenciais e a chave publica de identidade (Ed25519)
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userName VARCHAR(255) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL, -- Hash Argon2
    public_key TEXT NOT NULL     -- Chave Publica de Assinatura
);

-- Tabela de Mensagens Offline
-- Armazena pacotes E2EE cifrados para entrega posterior
CREATE TABLE mensagens_offline (
    id INT AUTO_INCREMENT PRIMARY KEY,
    remetente_username VARCHAR(255) NOT NULL,
    destinatario_username VARCHAR(255) NOT NULL,
    conteudo TEXT NOT NULL,      -- Payload E2EE (Nao legivel pelo servidor)
    data_envio TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
````
### 2. Configurar Variaveis de Ambiente

Crie um arquivo chamado `.env` na raiz da pasta do servidor (ao lado do `server.py`). Adicione as suas credenciais do banco de dados:

```env
DB_HOST=localhost
DB_DATABASE=chat_seguro
DB_USER=root
DB_PASSWORD=sua_senha_aqui
```

### 3. Instalar Dependencias Python

É altamente recomendado usar um ambiente virtual (`venv`) para isolar as bibliotecas.

#### Passo 3.1: Criar e Ativar o Ambiente Virtual

**No Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**No Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```
#### Passo 3.2: Instalar as Bibliotecas

Com o ambiente ativado, instale os pacotes necessários:
```bash
pip install websockets cryptography argon2-cffi mysql-connector-python python-dotenv
```
## Como Rodar

Certifique-se de que o MySQL está rodando e que você ativou o ambiente virtual.

No terminal, dentro da pasta do servidor, execute:

```bash
python server.py
```
Você deverá ver a mensagem: [*] Servidor Principal ouvindo em localhost:12345
