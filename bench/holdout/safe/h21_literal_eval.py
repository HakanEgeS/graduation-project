import ast


def parse_numbers(text: str):
    return ast.literal_eval(text)
