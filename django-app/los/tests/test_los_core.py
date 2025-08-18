# -*- coding: utf-8 -*-
import unittest
import datetime as dt
from unittest.mock import patch
from los import los_core


# Konstantní testovací data (nemění se během testů)
WHEN_ISO = "2025-01-17T17:00:00Z"
WHEN_DT = dt.datetime(2025, 1, 17, 17, 0, 0, tzinfo=dt.timezone.utc)

# Mockované odpovědi zdrojů entropie
NIST_JSON = {"pulse": {"outputValue": "d1" * 64, "timeStamp": "2025-01-17T17:00:00.000Z"}}
NIST_URL = "https://beacon.test/pulse/time/1758042000000"

DRAND_JSON = {"randomness": "e2" * 32}  # 64 hex znaků
DRAND_URL = "https://drand.test/public/123456"
DRAND_META = {"round": 123456, "info": {"period": 30, "genesis_time": 1595431050}}

BTC_META = {"height": 800000, "hash": "f3" * 32, "timestamp": 1737133200}
BTC_URL = "https://blockstream.info/block/" + ("f3" * 32)


class LosCoreTests(unittest.TestCase):
    def setUp(self):
        # Mockni všechny síťové zdroje, aby testy neběžely po internetu
        self.p_nist = patch("los.los_core.nist_pulse_at_minute", return_value=(NIST_JSON, NIST_URL))
        self.p_drand = patch("los.los_core.drand_randomness_for_time", return_value=(DRAND_JSON, DRAND_URL, DRAND_META))
        self.p_btc = patch("los.los_core.btc_block_at_or_before", return_value=(BTC_META, BTC_URL))

        self.p_nist.start()
        self.p_drand.start()
        self.p_btc.start()

    def tearDown(self):
        self.p_nist.stop()
        self.p_drand.stop()
        self.p_btc.stop()

    def test_determinism_same_inputs_same_output(self):
        a1 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False, base_url="http://example.com")
        a2 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False, base_url="http://example.com")
        self.assertEqual(a1["result"], a2["result"])
        self.assertEqual(a1["invocation"]["cli_verify"], a2["invocation"]["cli_verify"])
        self.assertEqual(a1["invocation"]["repro_url"], a2["invocation"]["repro_url"])

        # audit obsahuje očekávané sekce
        for key in ("nist", "drand", "btc_block"):
            self.assertIn(key, a1["sources"])
        self.assertIn("cli_verify", a1["invocation"])
        self.assertIn("repro_url", a1["invocation"])

    def test_changing_when_changes_result(self):
        a1 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False)
        a2 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso="2025-01-17T17:01:00Z", fair=False)
        self.assertNotEqual(a1["result"], a2["result"])

    def test_items_validation(self):
        with self.assertRaises(ValueError):
            los_core.compute_draw(items_csv="OnlyOne", when_used_iso=WHEN_ISO, fair=False)
        with self.assertRaises(ValueError):
            los_core.compute_draw(items_csv="A,A,B", when_used_iso=WHEN_ISO, fair=False)

    def test_build_web_verify_url(self):
        url_rel = los_core.build_web_verify_url(None, WHEN_ISO, ["A", "B", "C"])
        self.assertTrue(url_rel.startswith("/draw/?"))
        self.assertIn("items=A%2CB%2CC", url_rel)
        self.assertIn("when=2025-01-17T17%3A00%3A00Z", url_rel)
        self.assertIn("pretty=1", url_rel)

        url_abs = los_core.build_web_verify_url("http://example.com", WHEN_ISO, ["A", "B"])
        self.assertTrue(url_abs.startswith("http://example.com/draw/?"))

    def test_fair_mode_adds_commit(self):
        # fair používá předchozí minutu; abychom měli deterministiku, mockneme prev_full_minute
        with patch("los.los_core.prev_full_minute", return_value=WHEN_DT):
            a = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=None, fair=True)
            self.assertIn("commit", a)
            self.assertEqual(a["params"]["when_utc_minute"], WHEN_ISO)
            self.assertEqual(a["policy"]["third_source"], "btc_block")


if __name__ == "__main__":
    unittest.main()

