import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import public_route


class PublicRouteWitnessTests(unittest.TestCase):
    def test_requires_execution_witness_and_nonempty_success(self):
        address = public_route.ADDRESSES[0]
        witness = f"PUBLIC_ROUTE_VERIFIED {address}\n"
        success = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        public_route.check_result(witness + success, address)
        for output in [success, witness, witness + witness + success,
                       f"PUBLIC_ROUTE_VERIFIED {address}8\n" + success,
                       f"prefix PUBLIC_ROUTE_VERIFIED {address}\n" + success,
                       f"PUBLIC_ROUTE_VERIFIED {address} suffix\n" + success,
                       witness + "test result: ok. 0 passed; 0 failed; 1 ignored;\n",
                       witness + "test result: ok. 0 passed; 0 failed; 0 ignored;\n",
                       witness + success + success]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                public_route.check_result(output, address)

    def test_witness_for_another_address_is_rejected(self):
        with self.assertRaises(ValueError):
            public_route.check_result(
                f"PUBLIC_ROUTE_VERIFIED {public_route.ADDRESSES[1]}\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored;\n", public_route.ADDRESSES[0])

    def test_host_namespace_or_unverifiable_namespace_never_changes_interfaces(self):
        with patch.object(public_route.subprocess, "check_output", return_value='[{"ifname":"lo"}]'), \
                patch.object(public_route.os, "geteuid", return_value=0), \
                patch.object(public_route.subprocess, "run") as mutate:
            with patch.object(public_route.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=1)):
                with self.assertRaises(ValueError):
                    public_route.inside(Path("/unused-test-binary"), public_route.ADDRESSES[0])
            with patch.object(public_route.os, "stat", side_effect=PermissionError("cannot verify namespace")):
                with self.assertRaises(PermissionError):
                    public_route.inside(Path("/unused-test-binary"), public_route.ADDRESSES[0])
            mutate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
