import pickle
import yaml


def vulnerable_import(upload):
    return pickle.load(upload)


def safe_yaml_import(payload):
    return yaml.safe_load(payload)
