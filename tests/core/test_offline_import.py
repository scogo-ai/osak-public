import os
import subprocess
import sys


def test_offline_models_import_without_initializing_database() -> None:
    code = "import osak.core.models; assert 'osak.core.db' not in __import__('sys').modules"
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"DATABASE_URL": "postgresql://invalid.invalid/osak"},
    )
    assert result.returncode == 0, result.stderr
