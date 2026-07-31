"""
Fabric Gateway Client — Python wrapper for calling the Node.js REST gateway
Used by identity.py and app.py to interact with Hyperledger Fabric ledger
"""

import requests
import json
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class FabricGatewayClient:
    """HTTP client for communicating with the Fabric Gateway REST API"""

    def __init__(self, gateway_url: str = "http://localhost:3000", timeout: int = 10):
        """
        Initialize the Fabric Gateway client.

        Args:
            gateway_url: Base URL of the Node.js Fabric gateway (default: http://localhost:3000)
            timeout: Request timeout in seconds (default: 10)
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self, method: str, endpoint: str, json_data: Optional[Dict] = None
    ) -> Dict:
        """
        Make HTTP request to the gateway.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path (e.g., "/agents")
            json_data: Request body as dict

        Returns:
            Response JSON as dict

        Raises:
            ConnectionError: If gateway is unreachable
            ValueError: If response is invalid
        """
        url = urljoin(self.gateway_url, endpoint)

        try:
            response = requests.request(
                method,
                url,
                json=json_data,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.ConnectionError as e:
            logger.error(f"Failed to connect to Fabric gateway at {self.gateway_url}")
            raise ConnectionError(
                f"Fabric gateway unreachable at {self.gateway_url}: {str(e)}"
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Fabric gateway request failed: {str(e)}")
            raise ValueError(f"Fabric gateway error: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from Fabric gateway: {str(e)}")
            raise ValueError(f"Invalid response from gateway: {str(e)}")

    def health(self) -> Dict:
        """
        Check gateway health status.

        Returns:
            Health status dict with 'status', 'gateway', 'channel', 'chaincode'
        """
        return self._request("GET", "/health")

    def register_agent(
        self, did: str, public_key: str, role: str, credential_hash: str
    ) -> Dict:
        """
        Register a new agent on the Fabric ledger.

        Args:
            did: Decentralized Identifier (e.g., "did:example:xyz")
            public_key: Agent's public key
            role: Agent role (e.g., "admin", "user", "auditor")
            credential_hash: SHA256 hash of verifiable credential

        Returns:
            Agent data from ledger
        """
        payload = {
            "did": did,
            "publicKey": public_key,
            "role": role,
            "credentialHash": credential_hash,
        }
        return self._request("POST", "/agents", payload)

    def get_agent(self, did: str) -> Dict:
        """
        Retrieve agent details from the Fabric ledger.

        Args:
            did: Agent's DID

        Returns:
            Agent data from ledger
        """
        return self._request("GET", f"/agents/{did}")

    def get_all_agents(self) -> Dict:
        """
        Retrieve all registered agents from the Fabric ledger.

        Returns:
            Dict with 'count' and 'agents' list
        """
        return self._request("GET", "/agents")

    def is_revoked(self, did: str) -> bool:
        """
        Check if an agent is revoked on the Fabric ledger.
        Fast query used during authentication.

        Args:
            did: Agent's DID

        Returns:
            True if agent is revoked, False otherwise
        """
        result = self._request("GET", f"/agents/{did}/revoked")
        return result.get("isRevoked", False)

    def revoke_agent(self, did: str, reason: str = "") -> Dict:
        """
        Revoke an agent on the Fabric ledger.

        Args:
            did: Agent's DID
            reason: Reason for revocation

        Returns:
            Updated agent data from ledger
        """
        payload = {"reason": reason or "Not specified"}
        return self._request("POST", f"/agents/{did}/revoke", payload)

    def anchor_audit_batch(
        self,
        root_hash: str,
        event_count: int,
        period_start: str,
        period_end: str,
    ) -> Dict:
        """
        Anchor a batch of audit logs to the Fabric ledger.

        Args:
            root_hash: HMAC-SHA256 root hash of audit log chain
            event_count: Number of events in the batch
            period_start: ISO 8601 timestamp of batch start
            period_end: ISO 8601 timestamp of batch end

        Returns:
            Anchor data from ledger
        """
        payload = {
            "rootHash": root_hash,
            "eventCount": event_count,
            "periodStart": period_start,
            "periodEnd": period_end,
        }
        return self._request("POST", "/audit-anchors", payload)

    def get_audit_anchors(self) -> Dict:
        """
        Retrieve all audit batch anchors from the Fabric ledger.

        Returns:
            Dict with 'count' and 'anchors' list
        """
        return self._request("GET", "/audit-anchors")

    def get_audit_anchor(self, batch_id: str) -> Optional[Dict]:
        """
        Retrieve a single audit batch anchor by batch id.
        The chaincode only exposes getAuditAnchors() (no per-batch lookup),
        so this filters the full list — same ledger call, no second client.

        Args:
            batch_id: The anchor's batchId (periodStart_periodEnd)

        Returns:
            The matching anchor dict, or None if not found
        """
        anchors = self.get_audit_anchors().get("anchors", [])
        for anchor in anchors:
            if anchor.get("batchId") == batch_id:
                return anchor
        return None


# Global client instance (optional, for convenience)
_client = None


def get_fabric_client(gateway_url: str = "http://localhost:3000") -> FabricGatewayClient:
    """
    Get or create the Fabric gateway client singleton.

    Args:
        gateway_url: Base URL of the gateway (used on first call)

    Returns:
        FabricGatewayClient instance
    """
    global _client
    if _client is None:
        _client = FabricGatewayClient(gateway_url)
    return _client


# Convenience functions using the global client

def fabric_health() -> Dict:
    """Check Fabric gateway health."""
    return get_fabric_client().health()


def fabric_register_agent(
    did: str, public_key: str, role: str, credential_hash: str
) -> Dict:
    """Register agent on Fabric ledger."""
    return get_fabric_client().register_agent(did, public_key, role, credential_hash)


def fabric_is_revoked(did: str) -> bool:
    """Check if agent is revoked on Fabric ledger."""
    return get_fabric_client().is_revoked(did)


def fabric_revoke_agent(did: str, reason: str = "") -> Dict:
    """Revoke agent on Fabric ledger."""
    return get_fabric_client().revoke_agent(did, reason)


def fabric_anchor_audit_batch(
    root_hash: str, event_count: int, period_start: str, period_end: str
) -> Dict:
    """Anchor audit batch to Fabric ledger."""
    return get_fabric_client().anchor_audit_batch(
        root_hash, event_count, period_start, period_end
    )


def fabric_get_audit_anchors() -> Dict:
    """Get all audit anchors from Fabric ledger."""
    return get_fabric_client().get_audit_anchors()


def fabric_get_audit_anchor(batch_id: str) -> Optional[Dict]:
    """Get a single audit anchor by batch id from Fabric ledger."""
    return get_fabric_client().get_audit_anchor(batch_id)
