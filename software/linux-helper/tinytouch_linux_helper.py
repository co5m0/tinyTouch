#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import keyring
from bleak import BleakClient, BleakScanner

from tinytouch_protocol import encrypt_password, parse_event

SERVICE_UUID = "54a10000-7469-6e79-746f-756368000001"
RX_UUID = "54a10000-7469-6e79-746f-756368000002"
TX_UUID = "54a10000-7469-6e79-746f-756368000003"
SERVICE = "tinyTouch-linux"
STATE_PATH = Path.home() / ".local" / "state" / "tinytouch" / "seen.json"


def account(device: str, kind: str) -> str:
    return f"{device}:{kind}"


def set_secret(device: str, kind: str, value: str) -> None:
    keyring.set_password(SERVICE, account(device, kind), value)


def get_secret(device: str, kind: str) -> str:
    value = keyring.get_password(SERVICE, account(device, kind))
    if value is None:
        raise RuntimeError(f"missing {kind}; run setup for device {device}")
    return value


def load_seen() -> list[str]:
    try:
        value = json.loads(STATE_PATH.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    return [str(item).lower() for item in value][-256:]


def save_seen(seen: list[str]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(seen[-256:]))


async def find_device(name: str | None):
    if name:
        devices = await BleakScanner.discover(timeout=5.0)
        for device in devices:
            if device.address == name or device.name == name:
                return device
        raise RuntimeError(f"tinyTouch BLE device not found: {name}")
    device = await BleakScanner.find_device_by_filter(
        lambda d, ad: SERVICE_UUID.lower()
        in {value.lower() for value in (ad.service_uuids or [])},
        timeout=10.0,
    )
    if device is None:
        raise RuntimeError("no advertising tinyTouch BLE device found")
    return device


async def run(device_selector: str | None, once: bool) -> None:
    device = await find_device(device_selector)
    device_id = device.address
    pairing_key = bytes.fromhex(get_secret(device_id, "pairing-key"))
    password = get_secret(device_id, "password").encode("ascii")
    seen = load_seen()
    buffer = bytearray()
    finished = asyncio.Event()

    async with BleakClient(device) as client:
        mtu = getattr(client, "mtu_size", 23)
        write_chunk = max(20, min(244, mtu - 3))

        async def send_line(line: str) -> None:
            payload = (line + "\n").encode("ascii")
            for offset in range(0, len(payload), write_chunk):
                await client.write_gatt_char(
                    RX_UUID, payload[offset : offset + write_chunk], response=False
                )

        def notification(_sender, data: bytearray):
            nonlocal buffer
            buffer.extend(data)
            while b"\n" in buffer:
                raw, _, rest = buffer.partition(b"\n")
                buffer = bytearray(rest)
                try:
                    line = raw.rstrip(b"\r").decode("ascii")
                except UnicodeDecodeError:
                    continue
                event = parse_event(line, pairing_key)
                if event is None or event.nonce in seen:
                    continue
                reply = encrypt_password(pairing_key, event, password)

                async def deliver() -> None:
                    await send_line(reply)
                    seen.append(event.nonce)
                    save_seen(seen)
                    if once:
                        finished.set()

                asyncio.create_task(deliver())

        await client.start_notify(TX_UUID, notification)
        if once:
            await finished.wait()
        else:
            while client.is_connected:
                await asyncio.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="tinyTouch Linux BLE HID helper")
    parser.add_argument("--device", help="BLE address or advertised device name")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--set-pairing-key")
    parser.add_argument("--set-password")
    args = parser.parse_args()

    if args.set_pairing_key or args.set_password:
        if not args.device:
            raise SystemExit("--device is required when storing credentials")
        if args.set_pairing_key:
            key = bytes.fromhex(args.set_pairing_key)
            if len(key) != 32:
                raise SystemExit("pairing key must be 32 bytes / 64 hex characters")
            set_secret(args.device, "pairing-key", key.hex())
        if args.set_password:
            args.set_password.encode("ascii")
            set_secret(args.device, "password", args.set_password)
        return

    asyncio.run(run(args.device, args.once))


if __name__ == "__main__":
    main()
