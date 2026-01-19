from hashlib import sha1


def mysql_native_password_hash(password: bytes, salt: bytes) -> bytes:
    """
    SHA1( password ) XOR SHA1( "20-bytes public seed" <concat> SHA1( SHA1( password ) ) )
    """
    if not password:
        return b""

    if isinstance(password, str):
        password = password.encode("utf-8")

    stage1 = sha1(password).digest()
    stage2 = sha1(stage1).digest()

    # salt is bytes
    outer = sha1(salt + stage2).digest()

    # XOR
    result = bytearray(x ^ y for x, y in zip(stage1, outer))
    return bytes(result)
