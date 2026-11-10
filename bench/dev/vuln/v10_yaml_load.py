import yaml
def parse_config(text: str):
    return yaml.load(text, Loader=yaml.Loader)
