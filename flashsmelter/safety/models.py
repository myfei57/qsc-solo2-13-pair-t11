"""人员安全领域模型：区域目录、批条、在场记录与报警记录。

区域目录是代码常量（与 ``ns.ZONE_CATALOG`` 同一风格）：区域的新增与升降级属于
工艺变更，走版本评审，不允许运行期随口配置。禁区（restricted）进入必须在审批
中显式授权，定位事件发现未授权人员即触发闯入报警。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..errors import ValidationError

# 高温区物理分区。level=general 凭有效批条进入；level=restricted 为禁区，
# 批条必须显式带 allow_restricted 才放行。
ZONES: Mapping[str, Mapping[str, str]] = {
    "reactor-floor": {"label": "反应塔平台", "level": "general"},
    "settler-deck": {"label": "沉淀池平台", "level": "general"},
    "converter-aisle": {"label": "转炉跨", "level": "general"},
    "tapping-aisle": {"label": "放铜通道", "level": "restricted"},
    "oxygen-stand": {"label": "氧站", "level": "restricted"},
}

# 求助信号无法定位到具体区域时使用的全厂伪区域：只广播、不下发门禁指令。
PLANT_ZONE = "plant"

ALARM_KINDS = ("overstay", "intrusion", "sos")
ALARM_SEVERITIES = {"overstay": "major", "intrusion": "major", "sos": "critical"}
ALARM_STATUSES = ("active", "acknowledged", "resolved")

PASS_STATUSES = ("active", "revoked")
SESSION_STATUSES = ("inside", "exited")

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def require_token(value: str, label: str) -> str:
    """人员、批条、区域等标识必须能安全地作为落盘键段。"""

    if not isinstance(value, str) or not _ID_PATTERN.match(value):
        raise ValidationError(
            f"{label} 标识不合法",
            details={"value": repr(value), "expected": "字母数字开头，可含 _ . -，最长 64 字符"},
        )
    return value


def require_zone(zone: str) -> str:
    if zone not in ZONES:
        raise ValidationError("未知区域", details={"zone": zone, "known": sorted(ZONES)})
    return zone


def zone_label(zone: str) -> str:
    info = ZONES.get(zone)
    return info["label"] if info is not None else zone


def is_restricted(zone: str) -> bool:
    info = ZONES.get(zone)
    return bool(info) and info["level"] == "restricted"


@dataclass(slots=True)
class PassRecord:
    """进入批条：谁批的、批了多久、是否含禁区，全部留痕。"""

    pass_id: str
    person_id: str
    zone: str
    approver: str
    reason: str
    approved_at: str
    valid_until_epoch: float
    valid_until: str
    max_dwell_seconds: float
    allow_restricted: bool
    status: str = "active"
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass_id": self.pass_id,
            "person_id": self.person_id,
            "zone": self.zone,
            "approver": self.approver,
            "reason": self.reason,
            "approved_at": self.approved_at,
            "valid_until_epoch": self.valid_until_epoch,
            "valid_until": self.valid_until,
            "max_dwell_seconds": self.max_dwell_seconds,
            "allow_restricted": self.allow_restricted,
            "status": self.status,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "revoke_note": self.revoke_note,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PassRecord":
        return cls(
            pass_id=str(payload["pass_id"]),
            person_id=str(payload["person_id"]),
            zone=str(payload["zone"]),
            approver=str(payload.get("approver", "unknown")),
            reason=str(payload.get("reason", "")),
            approved_at=str(payload.get("approved_at", "")),
            valid_until_epoch=float(payload.get("valid_until_epoch", 0.0)),
            valid_until=str(payload.get("valid_until", "")),
            max_dwell_seconds=float(payload.get("max_dwell_seconds", 0.0)),
            allow_restricted=bool(payload.get("allow_restricted", False)),
            status=str(payload.get("status", "active")),
            revoked_at=payload.get("revoked_at"),
            revoked_by=payload.get("revoked_by"),
            revoke_note=payload.get("revoke_note"),
        )


@dataclass(slots=True)
class SessionRecord:
    """一次在场：进门落批条与审批人，出门补记滞留时长与是否超时。"""

    session_id: str
    person_id: str
    zone: str
    gate: str
    pass_id: str
    approver: str
    entered_at: str
    entered_epoch: float
    deadline_epoch: float
    max_dwell_seconds: float
    status: str = "inside"
    exited_at: str | None = None
    exited_epoch: float | None = None
    dwell_seconds: float | None = None
    overdue: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "person_id": self.person_id,
            "zone": self.zone,
            "gate": self.gate,
            "pass_id": self.pass_id,
            "approver": self.approver,
            "entered_at": self.entered_at,
            "entered_epoch": self.entered_epoch,
            "deadline_epoch": self.deadline_epoch,
            "max_dwell_seconds": self.max_dwell_seconds,
            "status": self.status,
            "exited_at": self.exited_at,
            "exited_epoch": self.exited_epoch,
            "dwell_seconds": self.dwell_seconds,
            "overdue": self.overdue,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SessionRecord":
        return cls(
            session_id=str(payload["session_id"]),
            person_id=str(payload["person_id"]),
            zone=str(payload["zone"]),
            gate=str(payload.get("gate", "")),
            pass_id=str(payload.get("pass_id", "")),
            approver=str(payload.get("approver", "unknown")),
            entered_at=str(payload.get("entered_at", "")),
            entered_epoch=float(payload.get("entered_epoch", 0.0)),
            deadline_epoch=float(payload.get("deadline_epoch", 0.0)),
            max_dwell_seconds=float(payload.get("max_dwell_seconds", 0.0)),
            status=str(payload.get("status", "inside")),
            exited_at=payload.get("exited_at"),
            exited_epoch=payload.get("exited_epoch"),
            dwell_seconds=payload.get("dwell_seconds"),
            overdue=bool(payload.get("overdue", False)),
        )


@dataclass(slots=True)
class AlarmRecord:
    """一条警情：类型、人员、区域、联动回执与处置闭环全部在案。"""

    alarm_id: str
    kind: str
    severity: str
    person_id: str
    zone: str
    summary: str
    raised_by: str
    raised_at: str
    raised_epoch: float
    details: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolve_note: str | None = None
    linkage: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alarm_id": self.alarm_id,
            "kind": self.kind,
            "severity": self.severity,
            "person_id": self.person_id,
            "zone": self.zone,
            "summary": self.summary,
            "raised_by": self.raised_by,
            "raised_at": self.raised_at,
            "raised_epoch": self.raised_epoch,
            "details": dict(self.details),
            "status": self.status,
            "acknowledged_at": self.acknowledged_at,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolve_note": self.resolve_note,
            "linkage": [dict(item) for item in self.linkage],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AlarmRecord":
        return cls(
            alarm_id=str(payload["alarm_id"]),
            kind=str(payload["kind"]),
            severity=str(payload.get("severity", "major")),
            person_id=str(payload.get("person_id", "")),
            zone=str(payload.get("zone", "")),
            summary=str(payload.get("summary", "")),
            raised_by=str(payload.get("raised_by", "unknown")),
            raised_at=str(payload.get("raised_at", "")),
            raised_epoch=float(payload.get("raised_epoch", 0.0)),
            details=dict(payload.get("details", {}) or {}),
            status=str(payload.get("status", "active")),
            acknowledged_at=payload.get("acknowledged_at"),
            acknowledged_by=payload.get("acknowledged_by"),
            resolved_at=payload.get("resolved_at"),
            resolved_by=payload.get("resolved_by"),
            resolve_note=payload.get("resolve_note"),
            linkage=[dict(item) for item in payload.get("linkage", []) or []],
        )


__all__ = [
    "ZONES",
    "PLANT_ZONE",
    "ALARM_KINDS",
    "ALARM_SEVERITIES",
    "ALARM_STATUSES",
    "PASS_STATUSES",
    "SESSION_STATUSES",
    "require_token",
    "require_zone",
    "zone_label",
    "is_restricted",
    "PassRecord",
    "SessionRecord",
    "AlarmRecord",
]
