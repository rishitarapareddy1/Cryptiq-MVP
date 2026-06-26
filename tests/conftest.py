"""
tests/conftest.py
-----------------
Shared pytest configuration.
Sets environment variables before any imports happen,
so the SSH scanner uses an in-memory DB during tests.
"""
import os
import sys

# Point SSH scanner at an in-memory DB for all tests
os.environ.setdefault("SSH_SCANNER_DATABASE_URL", "sqlite:///:memory:")

# Make sure the repo root is on the path so imports work
# when pytest is run from the repo root or from tests/
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)