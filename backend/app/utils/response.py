def ok(message: str, **kwargs):
    payload = {"message": message}
    payload.update(kwargs)
    return payload

