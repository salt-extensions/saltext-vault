import os

CONTAINER_TARGETS = os.environ.get(
    "TESTING_CONTAINER", "hashicorp/vault:latest,openbao/openbao:latest"
).split(",")

DEFAULT_ROOT_TOKEN = "testsecret"
