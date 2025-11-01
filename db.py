# Importa as bibliotecas necessárias
import mysql.connector
import os
from dotenv import load_dotenv
from mysql.connector import Error

# Carregamos as variáveis de ambiente do arquivo .env AQUI.
# Isso garante que a leitura do arquivo seja feita apenas uma vez,
# quando este módulo (database.py) for importado pela primeira vez.
load_dotenv()

class Database:
 
    def __init__(self):
        self.host = os.getenv('DB_HOST')
        self.database = os.getenv('DB_DATABASE')
        self.user = os.getenv('DB_USER')
        self.password = os.getenv('DB_PASSWORD')
        self.connection = None
        self.cursor = None
        print(f"Conexão com o banco de dados '{self.database}' estabelecida.")

    def connect(self):
        # Verifica se as variáveis de ambiente foram carregadas
        if not all([self.host, self.database, self.user, self.password]):
            print("Erro: Credenciais do banco de dados não encontradas no .env.")
            return False
            
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor(dictionary=True)
                return True
        except Error as e:
            print(f"Erro ao conectar ao MySQL: {e}")
            return False

    def disconnect(self):
        if self.connection and self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
            

    def __enter__(self):
        """
        Método para o gerenciador de contexto (bloco 'with'), que inicia a conexão.
        """
        if self.connect():
            return self
        else:
            # Retorna None se a conexão falhar, para que o bloco 'with' não execute
            return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Método para o gerenciador de contexto (bloco 'with'), que fecha a conexão.
        """
        self.disconnect()

    def fetch_all(self, query, params=None):
        try:
            self.cursor.execute(query, params or ())
            return self.cursor.fetchall()
        except Error as e:
            print(f"Erro ao executar a consulta: {e}")
            return []

    def execute_query(self, query, params=None):
        try:
            self.cursor.execute(query, params or ())
            self.connection.commit()
            print(f"{self.cursor.rowcount} linha(s) afetada(s).")
            return self.cursor.rowcount
        except Error as e:
            print(f"Erro ao executar a consulta: {e}")
            self.connection.rollback()
            return 0