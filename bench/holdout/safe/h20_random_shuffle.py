import random


def shuffle_quiz(questions: list) -> list:
    order = list(questions)
    random.shuffle(order)
    return order
