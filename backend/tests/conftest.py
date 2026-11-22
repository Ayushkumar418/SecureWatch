"""Shared pytest fixtures for the SecureWatch backend tests."""
import os
import sys

# Make `backend/` importable so tests can `import config`, `detection.*`, etc.
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
