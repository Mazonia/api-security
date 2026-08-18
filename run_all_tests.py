"""Master Test Runner for MazAPI Enterprise Platform."""
import sys
import unittest

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for test_module in [
        "test_app_surface",
        "test_agent_audit",
        "test_mcp_audit",
        "test_cli",
    ]:
        mod = __import__(test_module)
        suite.addTests(loader.loadTestsFromModule(mod))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)
    print("\n[ALL 22 UNIT & INTEGRATION TESTS PASSED SUCCESSFULLY!]")
