import unittest
from unittest.mock import patch

from main import _get_batch_previous_for_tenant


class AuditBatchChainTests(unittest.TestCase):
    def test_previous_lookup_is_isolated_per_tenant(self):
        cache = {}
        fake_db = object()

        with patch("main._latest_tenant_event") as latest:
            latest.side_effect = [None, None]

            _get_batch_previous_for_tenant(fake_db, cache, "tenant-a")
            _get_batch_previous_for_tenant(fake_db, cache, "tenant-b")
            _get_batch_previous_for_tenant(fake_db, cache, "tenant-a")

        self.assertEqual(latest.call_count, 2)
        self.assertEqual(latest.call_args_list[0].args[1], "tenant-a")
        self.assertEqual(latest.call_args_list[1].args[1], "tenant-b")


if __name__ == "__main__":
    unittest.main()
