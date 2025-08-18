# -*- coding: utf-8 -*-
from django.test import TestCase, Client
from unittest.mock import patch

# Minimální stub auditu, který view vrátí
STUB_AUDIT = {
    "version": 2,
    "mode": "items",
    "params": {"items": ["A", "B", "C"], "when_utc_minute": "2025-01-17T17:00:00Z"},
    "sources": {
        "nist": {"url": "https://beacon.test/pulse", "timeStamp": "2025-01-17T17:00:00.000Z"},
        "drand": {"url": "https://drand.test/public/123", "round": 123},
        "drand_info": {"url": "https://drand.test/info", "period": 30, "genesis_time": 1595431050},
        "btc_block": {"url": "https://blockstream.info/block/abc", "meta": {"height": 800000, "hash": "abc", "timestamp": 1737133200}},
    },
    "invocation": {
        "cli_verify": "python auditable_losovacka.py --when 2025-01-17T17:00:00Z --items A,B,C",
        "repro_url": "/draw/?items=A%2CB%2CC&when=2025-01-17T17%3A00%3A00Z&pretty=1",
    },
    "result": ["B", "C", "A"],
}

class DrawViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    @patch("los.views.los_core.compute_draw", return_value=STUB_AUDIT)
    def test_draw_endpoint_with_when(self, m_compute):
        resp = self.client.get("/draw/", {"items": "A,B,C", "when": "2025-01-17T17:00:00Z", "pretty": "1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["result"], ["B", "C", "A"])
        # ověř, že view předalo parametry správně
        m_compute.assert_called_once()
        kwargs = m_compute.call_args.kwargs
        self.assertEqual(kwargs["items_csv"], "A,B,C")
        self.assertEqual(kwargs["when_iso"], "2025-01-17T17:00:00Z")
        self.assertFalse(kwargs["fair"])

    @patch("los.views.los_core.compute_draw", return_value=STUB_AUDIT)
    def test_draw_endpoint_with_fair(self, m_compute):
        resp = self.client.get("/draw/", {"items": "A,B,C", "fair": "1"})
        self.assertEqual(resp.status_code, 200)
        m_compute.assert_called_once()
        self.assertTrue(m_compute.call_args.kwargs["fair"])

    def test_draw_requires_items(self):
        resp = self.client.get("/draw/", {"when": "2025-01-17T17:00:00Z"})
        self.assertEqual(resp.status_code, 400)

    def test_draw_requires_when_or_fair(self):
        resp = self.client.get("/draw/", {"items": "A,B,C"})
        self.assertEqual(resp.status_code, 400)

