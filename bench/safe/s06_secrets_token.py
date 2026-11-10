import secrets
def reset_token() -> str:
    return secrets.token_urlsafe(32)
