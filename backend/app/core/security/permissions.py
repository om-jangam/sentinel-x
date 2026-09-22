"""RBAC vocabulary (docs/07 §3): `resource:action` permissions and the default system roles.

Permissions are code-defined and synced into the database by `sentinelx seed`; each module adds
its own permissions here as it is built.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum


class Permission(StrEnum):
    PLATFORM_READ = "platform:read"
    AUDIT_READ = "audit:read"
    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    ROLE_READ = "role:read"
    ROLE_MANAGE = "role:manage"
    EVENT_READ = "event:read"
    SOURCE_READ = "source:read"
    SOURCE_MANAGE = "source:manage"
    INGEST_WRITE = "ingest:write"
    FINDING_READ = "finding:read"
    RULE_READ = "rule:read"
    INCIDENT_READ = "incident:read"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_RESOLVE = "incident:resolve"
    INTEL_READ = "intel:read"


PERMISSION_DESCRIPTIONS: Mapping[Permission, str] = {
    Permission.PLATFORM_READ: "View platform status and non-secret configuration",
    Permission.AUDIT_READ: "Read the audit log and verify its integrity",
    Permission.USER_READ: "List and view users",
    Permission.USER_MANAGE: "Create, update, deactivate users and assign their roles",
    Permission.ROLE_READ: "List and view roles and permissions",
    Permission.ROLE_MANAGE: "Create custom roles and change their permissions",
    Permission.EVENT_READ: "Search and view normalised security events",
    Permission.SOURCE_READ: "View ingest sources and their health",
    Permission.SOURCE_MANAGE: "Register ingest sources, rotate their tokens, enable or disable them",
    Permission.INGEST_WRITE: "Submit events through the HTTP ingest API",
    Permission.FINDING_READ: "View detection findings and the events they cite",
    Permission.RULE_READ: "View the loaded detection rules",
    Permission.INCIDENT_READ: "View incidents, their evidence links and entities",
    Permission.INCIDENT_UPDATE: "Move incidents into investigation",
    Permission.INCIDENT_RESOLVE: "Close incidents with a resolution, or reopen closed ones",
    Permission.INTEL_READ: "View cached threat intelligence and the configured providers",
}

# Granting these to a machine principal would let a compromised agent escalate itself (docs/07 §3).
PRIVILEGED_PERMISSIONS: frozenset[Permission] = frozenset({Permission.USER_MANAGE, Permission.ROLE_MANAGE})


class SystemRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    DETECTION_ENGINEER = "detection_engineer"
    ADMIN = "admin"
    SERVICE = "service"


SYSTEM_ROLE_DESCRIPTIONS: Mapping[SystemRole, str] = {
    SystemRole.VIEWER: "Read-only access to dashboards and incidents",
    SystemRole.ANALYST: "Tier-1 SOC analyst: triage and investigate",
    SystemRole.SENIOR_ANALYST: "Tier-2/3 analyst: resolve incidents, review the audit trail",
    SystemRole.INCIDENT_RESPONDER: "Lead incident investigations and manage investigation status",
    SystemRole.DETECTION_ENGINEER: "Author, test and promote detection content",
    SystemRole.ADMIN: "Full platform administration",
    SystemRole.SERVICE: "Least-privilege machine principal (agents, integrations)",
}

_READ_ONLY = frozenset(
    {
        Permission.PLATFORM_READ,
        Permission.EVENT_READ,
        Permission.FINDING_READ,
        Permission.INCIDENT_READ,
        Permission.INTEL_READ,
    }
)
_SOC = _READ_ONLY | {Permission.SOURCE_READ, Permission.RULE_READ, Permission.INCIDENT_UPDATE}

SYSTEM_ROLE_PERMISSIONS: Mapping[SystemRole, frozenset[Permission]] = {
    SystemRole.VIEWER: _READ_ONLY,
    SystemRole.ANALYST: _SOC,
    SystemRole.SENIOR_ANALYST: _SOC | {Permission.AUDIT_READ, Permission.INCIDENT_RESOLVE},
    SystemRole.INCIDENT_RESPONDER: _SOC | {Permission.INCIDENT_RESOLVE},
    SystemRole.DETECTION_ENGINEER: _SOC | {Permission.SOURCE_MANAGE},
    SystemRole.ADMIN: frozenset(Permission),
    # Integrations push telemetry; they never administer sources or read the audit trail.
    SystemRole.SERVICE: frozenset({Permission.PLATFORM_READ, Permission.EVENT_READ, Permission.INGEST_WRITE}),
}
