"""
Trust Layer — ABAC policy and session authorization.
"""

from typing import Dict, List, Optional


class TrustManager:
    def __init__(self, db):
        self.db = db
        self.abac_policy = {
            "admin":   ["access_protected", "view_logs", "manage_agents", "revoke_credentials"],
            "user":    ["access_protected"],
            "auditor": ["view_logs", "access_protected"],
            "guest":   []
        }
        self.resources = {
            "access_protected":  "Protected AI Agent Endpoint",
            "view_logs":         "Audit Logs Access",
            "manage_agents":     "Agent Management",
            "revoke_credentials":"Credential Revocation"
        }

    def is_authorized(self, role: str, resource: str) -> bool:
        return resource in self.abac_policy.get(role, [])

    def validate_role(self, role: str) -> bool:
        return role in self.abac_policy

    def get_all_roles(self) -> List[str]:
        return list(self.abac_policy.keys())

    def get_policy_summary(self) -> Dict:
        return {"policy": self.abac_policy, "resources": self.resources}

    def check_session_authorization(self, session_token: str, resource: str):
        session_data = self.db.get_session(session_token)
        if not session_data:
            return False, None, "Invalid or expired session token"
        agent_did, role = session_data
        if not self.is_authorized(role, resource):
            return False, agent_did, f"Role '{role}' not authorized for '{resource}'"
        return True, agent_did, None
