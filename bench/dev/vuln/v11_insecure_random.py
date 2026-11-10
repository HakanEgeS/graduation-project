import random, string
def reset_token() -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(32))
