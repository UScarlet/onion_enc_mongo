from pymongo import MongoClient
from pymongo.server_api import ServerApi


# Подключаемся к прокси (а не напрямую к MongoDB)
'''
информация из https://specifications.readthedocs.io/en/latest/mongodb-handshake/handshake/
If a server API version is requested or loadBalanced: True, 
drivers MUST use the hello command for the initial handshake and use the OP_MSG protocol
поэтому сервер апи передавать, но пока не очень поняла, что это
'''
client = MongoClient(
    "mongodb://localhost:27018",
    server_api=ServerApi("1")
)

db = client.test_proxy
collection = db.test

# Вставка
result = collection.insert_one({'name': 'proxy_check', 'value': 42})
print(f'Inserted id: {result.inserted_id}')

# Чтение
doc = collection.find_one({'name': 'proxy_check'})
print(f'Found: {doc}')

# Удаление тестовых данных
collection.delete_one({'name': 'proxy_check'})