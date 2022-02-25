from datetime import datetime
from datetime import timezone

from jwt import encode as encode_jwt

import typer


def load_file(private_key_file: str):
    from cryptography.hazmat.primitives import serialization

    key_data = None
    with open(private_key_file, "rb") as fp:
        key_data = fp.read()

    if not key_data:
        raise ValueError("No data for private key.")

    key_priv = serialization.load_pem_private_key(key_data, password=None)
    return key_priv


def main(
    private_key: str,
    client_id: str,
    team_id: str,
    key_id: str,
    lifetime: int,
):
    key_priv = private_key.encode("ascii")
    now_utc = datetime.now(tz=timezone.utc)
    now_utc_timestamp = now_utc.timestamp()
    exp_utc_timestamp = now_utc_timestamp + lifetime

    payload = {
        "iss": team_id,
        "iat": now_utc_timestamp,
        "exp": exp_utc_timestamp,
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    }
    token = encode_jwt(
        payload=payload, key=key_priv, algorithm="ES256", headers={"kid": key_id}
    )

    typer.echo(token)


def cli():
    typer.run(main)


if __name__ == "__main__":
    typer.run(main)
