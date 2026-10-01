from __future__ import annotations

import unittest

from release_chain.acceptance import run


class ReleaseChainAcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["shipped_conclusion_after_revocation"], "released")
        self.assertEqual(result["pending_config_blocked_after_revocation"], "blocked")
        self.assertEqual(
            result["reworked_serial_events"],
            ["installed", "removed", "reworked", "installed"])
        self.assertEqual(result["schema"]["missing_tables"], [])
        self.assertEqual(result["schema"]["schema_version"], "1")
        self.assertEqual(len(result["schema"]["immutability_triggers"]), 10)


if __name__ == "__main__":
    unittest.main()
