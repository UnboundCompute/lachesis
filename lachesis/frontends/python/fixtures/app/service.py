"""Cross-module calls: a chain deep enough for hubs to rank."""

from app.repository import Repository, open_repository
from app.util.text import greet as say_hello
from app.util import text

SERVICE_NAME = "fixture-service"


def build_service(connection):
    repository = open_repository(connection, cached=True)
    return Service(repository)


class Service:
    def __init__(self, repository):
        self.repository = repository

    def welcome(self, name):
        return say_hello(name)

    def describe(self, key):
        record = self.repository.fetch(key)
        return text.normalize(record)


def run(connection, name):
    service = build_service(connection)
    return service.welcome(name)


def unused_helper(value):
    return Repository.store
