# los/tests/test_determinism.py
# -*- coding: utf-8 -*-
import io
import json
import sys
from importlib import import_module
import datetime as dt
from unittest import TestCase
from unittest.mock import patch

from importlib.util import spec_from_file_location, module_from_spec
from django.conf import settings
from pathlib import Path

from los import los_core


WHEN_ISO = "2025-01-17T17:00:00Z"
WHEN_DT  = dt.datetime(2025, 1, 17, 17, 0, 0, tzinfo=dt.timezone.utc)

# Stabilní mock data (bez sítě)
NIST_JSON = {"pulse": {"outputValue": "d1"*64, "timeStamp": "2025-01-17T17:00:00.000Z"}}
NIST_URL  = "https://beacon.test/pulse/time/1758042000000"
DRAND_JSON = {"randomness": "e2"*32}
DRAND_URL  = "https://drand.test/public/123456"
DRAND_META = {"round": 123456, "info": {"period": 30, "genesis_time": 1595431050}}
BTC_META   = {"height": 800000, "hash": "f3"*32, "timestamp": 1737133200}
BTC_URL    = "https://blockstream.info/block/" + ("f3"*32)


class DeterminismCoreTests(TestCase):
    def setUp(self):
        self.p1 = patch("los.los_core.nist_pulse_at_minute", return_value=(NIST_JSON, NIST_URL))
        self.p2 = patch("los.los_core.drand_randomness_for_time", return_value=(DRAND_JSON, DRAND_URL, DRAND_META))
        self.p3 = patch("los.los_core.btc_block_at_or_before", return_value=(BTC_META, BTC_URL))
        for p in (self.p1, self.p2, self.p3):
            p.start()

    def tearDown(self):
        for p in (self.p1, self.p2, self.p3):
            p.stop()

    def test_same_inputs_same_output(self):
        a1 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False, base_url="http://example.com")
        a2 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False, base_url="http://example.com")
        self.assertEqual(a1["result"], a2["result"])
        self.assertEqual(a1["invocation"]["cli_verify"], a2["invocation"]["cli_verify"])
        self.assertEqual(a1["invocation"]["repro_url"], a2["invocation"]["repro_url"])

    def test_changing_when_changes_result(self):
        a1 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=WHEN_ISO, fair=False)
        a2 = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso="2025-01-17T17:01:00Z", fair=False)
        self.assertNotEqual(a1["result"], a2["result"])

    def test_fair_mode_adds_commit(self):
        with patch("los.los_core.prev_full_minute", return_value=WHEN_DT):
            a = los_core.compute_draw(items_csv="A,B,C,D", when_used_iso=None, fair=True)
            self.assertIn("commit", a)
            self.assertEqual(a["params"]["when_utc_minute"], WHEN_ISO)


class DeterminismCliVsCoreTests(TestCase):
    """
    Porovnání CLI vs. core v jednom procesu (kvůli mockům, bez subprocess).
    """

    def setUp(self):
        # cesta na <BASE_DIR>/../script (script je mimo BASE_DIR – o úroveň výš)
        script_dir = Path(settings.BASE_DIR).parent / "script"
        assert (script_dir / "auditable_losovacka.py").exists(), f"Soubor nenalezen: {script_dir}/auditable_losovacka.py"

        self._script_path = str(script_dir)
        self._script_path_added = False
        if self._script_path not in sys.path:
            sys.path.insert(0, self._script_path)
            self._script_path_added = True

        # normální import
        self.cli = import_module("auditable_losovacka")

        # mocky pro CLI modul los_core.py
        self.p1 = patch.object(self.cli, "nist_pulse_at_minute", return_value=(NIST_JSON, NIST_URL))
        self.p2 = patch.object(self.cli, "drand_randomness_for_time", return_value=(DRAND_JSON, DRAND_URL, DRAND_META))
        self.p3 = patch.object(self.cli, "btc_block_at_or_before", return_value=(BTC_META, BTC_URL))

        # stejné mocky pro script auditovatelna_losovacka.py jako pro los_core.py
        self.p1c = patch("los.los_core.nist_pulse_at_minute", return_value=(NIST_JSON, NIST_URL))
        self.p2c = patch("los.los_core.drand_randomness_for_time", return_value=(DRAND_JSON, DRAND_URL, DRAND_META))
        self.p3c = patch("los.los_core.btc_block_at_or_before", return_value=(BTC_META, BTC_URL))

        for p in (self.p1, self.p2, self.p3, self.p1c, self.p2c, self.p3c):
            p.start()

    def tearDown(self):
        for p in (self.p1, self.p2, self.p3, self.p1c, self.p2c, self.p3c):
            p.stop()

    def _run_cli_and_get_audit(self, items_csv: str, when_used_iso: str) -> dict:
        old_argv = sys.argv[:]
        sys.argv = ["auditable_losovacka.py", "--items", items_csv, "--when", when_used_iso]
        try:
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                self.cli.main()
            finally:
                sys.stdout = old_stdout
            out = buf.getvalue()
        finally:
            sys.argv = old_argv

        marker = "--- JSON AUDIT ---"
        pos = out.find(marker)
        if pos == -1:
            self.fail(f"CLI output neobsahuje marker '{marker}'. Output:\n{out}")
        json_text = out[pos + len(marker):].strip()
        return json.loads(json_text)

    def test_cli_matches_core(self):
        items = "A,B,C,D"
        when = WHEN_ISO

        core_audit = los_core.compute_draw(items_csv=items, when_used_iso=when, fair=False, base_url="http://example.com")
        cli_audit  = self._run_cli_and_get_audit(items, when)

        # debug: ověř, že seed je identický
        self.assertEqual(core_audit["seed_material_preview"], cli_audit["seed_material_preview"])

        self.assertEqual(core_audit["result"], cli_audit["result"])
        self.assertEqual(core_audit["params"]["when_utc_minute"], cli_audit["params"]["when_utc_minute"])
        self.assertEqual(core_audit["sources"]["nist"]["url"], cli_audit["sources"]["nist"]["url"])
        self.assertEqual(core_audit["sources"]["drand"]["url"], cli_audit["sources"]["drand"]["url"])
        self.assertEqual(core_audit["sources"]["btc_block"]["url"], cli_audit["sources"]["btc_block"]["url"])

