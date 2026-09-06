import hashlib
import hmac
import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "software" / "linux-helper" / "tinytouch_protocol.py"
SPEC = importlib.util.spec_from_file_location("tinytouch_protocol", PATH)
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
assert SPEC.loader is not None
SPEC.loader.exec_module(protocol)


class LinuxBleProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.nonce = "11" * 16

    def test_parse_v1_event(self):
        material = f"EV|{self.nonce}|7|2|123"
        mac = hmac.new(self.key, material.encode("ascii"), hashlib.sha256).hexdigest()
        event = protocol.parse_event(
            f"EV {self.nonce} 7 2 123 {mac}", self.key
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.slot, 2)
        self.assertEqual(event.version, 1)

    def test_parse_v2_selects_our_host_key(self):
        key_id = hashlib.sha256(self.key).hexdigest()[:16]
        material = f"EV2|{key_id}|{self.nonce}|8|1|456"
        mac = hmac.new(self.key, material.encode("ascii"), hashlib.sha256).hexdigest()
        event = protocol.parse_event(
            f"EV2 {self.nonce} 8 1 456 deadbeefdeadbeef:{'00' * 32} {key_id}:{mac}",
            self.key,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.key_id, key_id)

    def test_rejects_bad_mac(self):
        event = protocol.parse_event(
            f"EV {self.nonce} 7 2 123 {'00' * 32}", self.key
        )
        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
