"""Canonical NetWitness integration API."""

from .auth import AUTH_STYLES, NetWitnessConfig, decode_legacy_password
from .client import NetWitnessClient
from .diagnostics import NetWitnessError

__all__ = ["AUTH_STYLES", "NetWitnessClient", "NetWitnessConfig", "NetWitnessError", "decode_legacy_password"]
