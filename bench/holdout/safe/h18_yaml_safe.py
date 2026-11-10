import yaml


def parse_config(text: str):
    return yaml.safe_load(text)
