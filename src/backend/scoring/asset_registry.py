"""
Critical asset registry — lookup table for the asset_criticality scoring component.

Assets in this list receive a higher criticality multiplier (1.5×),
driving up the risk score for incidents targeting critical infrastructure.
"""
from __future__ import annotations

# Simulated critical asset list (representative names for demo)
CRITICAL_ASSETS: set[str] = {
    # Domain controllers / AD servers
    "srv-dc01", "srv-dc02", "dc-primary", "ad-server",
    # Satellite ground stations
    "ZONE-ALPHA-7", "ZONE-ALPHA-8", "ground-station-01",
    # Database / payment servers
    "db-server-01", "db-primary", "payment-srv",
    # VPN / network gateways
    "vpn-gw01", "vpn-gw02", "fw-perimeter",
    # Finance systems
    "ws-finance-03", "erp-server-01",
    # Vessels / objects of interest
    "VESSEL-IMO-9876543",
}

_CRITICALITY_HIGH = 100.0
_CRITICALITY_NORMAL = 50.0


def get_asset_criticality(asset: str) -> float:
    """
    Return the criticality score (0–100) for an asset.
    Critical assets return 100.0; all others return 50.0.
    """
    if not asset:
        return _CRITICALITY_NORMAL
    # Exact match or partial match for IP ranges / hostnames
    asset_lower = asset.lower().strip()
    for ca in CRITICAL_ASSETS:
        if ca.lower() in asset_lower or asset_lower in ca.lower():
            return _CRITICALITY_HIGH
    return _CRITICALITY_NORMAL
