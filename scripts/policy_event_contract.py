"""Shared public audit-event vocabulary for the demo policy wrapper."""

from __future__ import annotations

from typing import Final

ACTION_CAPABILITIES: Final[dict[str, str]] = {
    "read_docs": "read",
    "edit_docs": "write",
    "publish_release": "artifact.publish",
    "force_push": "push.force",
}

PUBLIC_AUDIT_CAPABILITIES: Final = frozenset(ACTION_CAPABILITIES.values())
