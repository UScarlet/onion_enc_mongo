from pymongo import MongoClient
from pymongo.server_api import ServerApi


# Подключаемся к прокси (а не напрямую к MongoDB)
'''
информация из https://specifications.readthedocs.io/en/latest/mongodb-handshake/handshake/
If a server API version is requested or loadBalanced: True, 
drivers MUST use the hello command for the initial handshake and use the OP_MSG protocol
поэтому сервер апи передавать, но пока не очень поняла, что это #TODO
'''
client = MongoClient(
    "mongodb://localhost:27018",
    server_api=ServerApi("1")
)

db = client.test_proxy
collection = db.test

test_doc = {
    "name": "proxy_check",
    "email": "proxy_check@example.com",
    "salary": 42,
    "age": 20,
}

test_filter = {
    "name": "proxy_check",
    "email": "proxy_check@example.com",
    "salary": 42,
    "age": 20,
}

# Вставка
result = collection.insert_one(test_doc)
print(f"Inserted id: {result.inserted_id}")

# Чтение
doc = collection.find_one(test_filter)
print(f"Found: {doc}")

# Удаление тестовых данных
delete_result = collection.delete_one(test_filter)
print(f"Deleted count: {delete_result.deleted_count}")