from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

MAX_PASSWORD_BYTES = 160


@dataclass(frozen=True)
class Event:
    version: int
    nonce: str
    counter: int
    slot: int
    score: int
    key_id: str | None


def key_id(pairing_key: bytes) -> str:
    return hashlib.sha256(pairing_key).hexdigest()[:16]


def mac_hex(pairing_key: bytes, material: str) -> str:
    return hmac.new(pairing_key, material.encode("ascii"), hashlib.sha256).hexdigest()


def parse_event(line: str, pairing_key: bytes) -> Event | None:
    parts = line.strip().split()
    if not parts or parts[0] not in {"EV", "EV2"}:
        return None
    version = 1 if parts[0] == "EV" else 2
    if version == 1 and len(parts) != 6:
        return None
    if version == 2 and len(parts) < 6:
        return None
    nonce, counter_text, slot_text, score_text = parts[1:5]
    try:
        if len(bytes.fromhex(nonce)) != 16:
            return None
        counter, slot, score = int(counter_text), int(slot_text), int(score_text)
    except (ValueError, TypeError):
        return None
    if not (0 <= counter < 2**64 and 1 <= slot <= 5 and 0 <= score < 2**31):
        return None

    if version == 1:
        authenticator = parts[5].lower()
        material = f"EV|{nonce}|{counter_text}|{slot_text}|{score_text}"
        selected_id = None
    else:
        selected_id = key_id(pairing_key)
        authenticators: dict[str, str] = {}
        for item in parts[5:]:
            if ":" not in item:
                return None
            host_id, authenticator = item.split(":", 1)
            if len(host_id) != 16 or host_id.lower() in authenticators:
                return None
            authenticators[host_id.lower()] = authenticator.lower()
        authenticator = authenticators.get(selected_id, "")
        material = f"EV2|{selected_id}|{nonce}|{counter_text}|{slot_text}|{score_text}"

    if len(authenticator) != 64:
        return None
    expected = mac_hex(pairing_key, material)
    if not hmac.compare_digest(expected, authenticator):
        return None
    return Event(version, nonce.lower(), counter, slot, score, selected_id)


def encrypt_password(pairing_key: bytes, event: Event, password: bytes) -> str:
    if len(password) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password exceeds {MAX_PASSWORD_BYTES} bytes")
    password.decode("ascii")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    session = hmac.new(
        pairing_key, f"SESSION|{event.nonce}".encode("ascii"), hashlib.sha256
    ).digest()
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(session), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(password) + encryptor.finalize()
    iv_hex = iv.hex()
    ct_hex = ciphertext.hex()

    if event.version == 1:
        material = f"PW|{event.nonce}|{iv_hex}|{ct_hex}"
        return f"PW {event.nonce} {iv_hex} {ct_hex} {mac_hex(pairing_key, material)}"

    assert event.key_id is not None
    material = f"PW2|{event.key_id}|{event.nonce}|{iv_hex}|{ct_hex}"
    return (
        f"PW2 {event.key_id} {event.nonce} {iv_hex} {ct_hex} "
        f"{mac_hex(pairing_key, material)}"
    )
