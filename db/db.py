from pymongo import MongoClient


class Connection:
    def __new__(cls, database):
        connection = MongoClient("mongodb+srv://ashan:ashan123@cluster0.f7hw40s.mongodb.net")

        if database is None:
            return connection

        return connection[database]
