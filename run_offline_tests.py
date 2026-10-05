"""Run only the sidecar mocked suite; OS network and subprocesses are forbidden."""
import json
from pathlib import Path
import platform
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))


def offline(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname',
                 'socket.gethostbyaddr', 'subprocess.Popen', 'os.system'}:
        raise RuntimeError('offline_suite_forbids_network_and_subprocesses')


sys.addaudithook(offline)
modules = ['test_sidecar_contract', 'test_sidecar_collector', 'test_sidecar_metadata',
           'test_sidecar_transport', 'test_sidecar_admission', 'test_sidecar_supervisor']
suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
start = time.monotonic()
# packaging evaluates complete supplied markers after consulting host defaults.
# Avoid Windows platform.py's fallback cmd.exe probe in this fully mocked suite.
# Deliberately different from the frozen Linux target to expose fallback errors.
fake_host = SimpleNamespace(system='Windows', node='offline-fixture', release='0',
                            version='0', machine='ARM64', processor='')
with patch('platform.uname', return_value=fake_host):
    result = unittest.TextTestRunner(verbosity=2).run(suite)
import packaging
print(json.dumps(dict(schema='sidecar_offline_test_result_v1', tests=result.testsRun,
    failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
    successful=result.wasSuccessful(), seconds=round(time.monotonic()-start, 6),
    python=sys.version, executable=sys.executable, platform=sys.platform,
    packaging=packaging.__version__, modules=modules,
    network_and_subprocess_audit_deny=True, platform_uname_mocked=True, execution_authorized=False,
    native_linux_compatibility_verified=False), indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
