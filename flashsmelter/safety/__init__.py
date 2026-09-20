"""高温区人员安全组件。

高温区过去靠门口挂牌子管人：谁进去了、进去多久全靠自觉，人在里面中暑都没人知道。
本组件把人员安全纳入平台联锁口径：

* 进入必须持有效许可——谁批的、批了多久、作业还是救援，全部落盘留痕；
* 进出逐次登记，``sweep`` 扫描发现超时未出立即报警（由调度方定时驱动）；
* 禁区闯入与求助按钮随时上报随时报警，未登记人员的求助同样受理；
* 报警即联动：广播按级别播报，门禁按区域切到封锁/疏散模式，回执随报警留痕；
* 报警未解除前禁止新的进入（救援许可除外），全部解除后区域自动恢复常态。
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping

from ..component import Component, ensure_actor
from ..errors import GuardViolation, NotFoundError, ValidationError
from ..machine import StateMachine
from ..ports import AccessControlPort, BroadcastPort
from ..runtime import RuntimeContext, iso_from_epoch

STATES = ("watching", "alarming")

TRANSITIONS: Mapping[str, tuple[str, ...]] = {
    "watching": ("alarming",),
    "alarming": ("watching",),
}

PERMIT_KINDS = ("work", "rescue")
ALARM_KINDS = ("overstay", "intrusion", "sos")
ALARM_ACTIVE = ("active", "acknowledged")
MAIN_ZONE = "hot-zone"
EVENTS_STREAM = "safety/events"


class PersonnelSafety(Component):
    name = "safety"

    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        broadcast: BroadcastPort,
        access: AccessControlPort,
    ) -> None:
        super().__init__(ctx)
        self._machine = StateMachine("safety", "watching", TRANSITIONS, ctx.clock)
        self._broadcast = broadcast
        self._access = access
        self._occupants: dict[str, dict[str, Any]] = {}
        self._alarms: dict[str, dict[str, Any]] = {}
        self._entries_total = 0
        self._exits_total = 0
        self._alarms_raised_total = 0
        restored = self.restore()
        if restored is not None:
            self._machine.restore(restored)
            occupants = restored.get("occupants")
            if isinstance(occupants, dict):
                self._occupants = {
                    str(key): dict(value) for key, value in occupants.items() if isinstance(value, Mapping)
                }
            alarms = restored.get("alarms")
            if isinstance(alarms, dict):
                self._alarms = {
                    str(key): dict(value) for key, value in alarms.items() if isinstance(value, Mapping)
                }
            self._entries_total = int(restored.get("entries_total", 0))
            self._exits_total = int(restored.get("exits_total", 0))
            self._alarms_raised_total = int(restored.get("alarms_raised_total", 0))
        self._refresh_gauges()

    # ------------------------------------------------------------------ 许可
    def issue_permit(
        self,
        actor: str,
        *,
        person_id: str,
        approved_by: str,
        kind: str = "work",
        max_dwell_seconds: float | None = None,
        valid_seconds: float | None = None,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        permit_id = "P-" + uuid.uuid4().hex[:12]
        with self.action(
            "issue_permit",
            f"safety/permit/{permit_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            if not person_id:
                raise ValidationError("许可必须绑定人员")
            if not approved_by:
                raise ValidationError("许可必须填写审批人")
            if kind not in PERMIT_KINDS:
                raise ValidationError(
                    "非法的许可类型", details={"kind": kind, "allowed": list(PERMIT_KINDS)}
                )
            dwell = (
                self.settings.safety_default_max_dwell_seconds
                if max_dwell_seconds is None
                else float(max_dwell_seconds)
            )
            if dwell <= 0:
                raise GuardViolation("许可停留时长必须为正", details={"max_dwell_seconds": dwell})
            if dwell > self.settings.safety_max_dwell_cap_seconds:
                raise GuardViolation(
                    "许可停留时长超过平台上限",
                    details={
                        "max_dwell_seconds": dwell,
                        "cap": self.settings.safety_max_dwell_cap_seconds,
                    },
                )
            valid = (
                self.settings.safety_permit_valid_seconds
                if valid_seconds is None
                else float(valid_seconds)
            )
            if valid <= 0:
                raise GuardViolation("许可有效期必须为正", details={"valid_seconds": valid})
            now = self.clock.timestamp()
            payload = {
                "permit_id": permit_id,
                "person_id": person_id,
                "kind": kind,
                "approved_by": approved_by,
                "issued_by": actor,
                "issued_at": self.clock.timestamp_iso(),
                "issued_epoch": now,
                "valid_until": iso_from_epoch(now + valid),
                "valid_until_epoch": now + valid,
                "max_dwell_seconds": dwell,
                "revoked": False,
                "revoked_at": None,
                "revoked_by": None,
                "revoke_reason": None,
            }
            record = self.store.commit_intent(self.key("permit", permit_id), payload)
            self._append_event(
                "permit-issued",
                {
                    "permit_id": permit_id,
                    "person_id": person_id,
                    "approved_by": approved_by,
                    "permit_kind": kind,
                    "max_dwell_seconds": dwell,
                    "valid_until": payload["valid_until"],
                    "actor": actor,
                },
            )
            trace.attach(record).note("person_id", person_id).note("approved_by", approved_by).note("kind", kind)
            return dict(payload)

    def revoke_permit(
        self,
        actor: str,
        *,
        permit_id: str,
        reason: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "revoke_permit",
            f"safety/permit/{permit_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            permit = self._require_permit(permit_id)
            if permit["revoked"]:
                raise GuardViolation("许可已注销", details={"permit_id": permit_id})
            if not reason:
                raise GuardViolation("注销许可必须填写原因")
            holder = self._occupants.get(str(permit["person_id"]))
            if holder is not None and holder["permit_id"] == permit_id:
                raise GuardViolation(
                    "许可持有人仍在高温区内，禁止注销",
                    details={"permit_id": permit_id, "person_id": permit["person_id"]},
                )
            permit.update(
                {
                    "revoked": True,
                    "revoked_at": self.clock.timestamp_iso(),
                    "revoked_by": actor,
                    "revoke_reason": reason,
                }
            )
            record = self.store.commit_intent(self.key("permit", permit_id), permit)
            self._append_event(
                "permit-revoked",
                {
                    "permit_id": permit_id,
                    "person_id": permit["person_id"],
                    "reason": reason,
                    "actor": actor,
                },
            )
            trace.attach(record).note("reason", reason)
            return dict(permit)

    # ------------------------------------------------------------------ 进出登记
    def enter(
        self,
        actor: str,
        *,
        person_id: str,
        permit_id: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "enter",
            f"safety/person/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            permit = self._require_permit(permit_id)
            if permit["person_id"] != person_id:
                raise GuardViolation(
                    "许可与人员不匹配",
                    details={"permit_person": permit["person_id"], "person_id": person_id},
                )
            if permit["revoked"]:
                raise GuardViolation("许可已注销，禁止进入", details={"permit_id": permit_id})
            now = self.clock.timestamp()
            if now >= float(permit["valid_until_epoch"]):
                raise GuardViolation(
                    "许可已过有效期，禁止进入",
                    details={"permit_id": permit_id, "valid_until": permit["valid_until"]},
                )
            if person_id in self._occupants:
                raise GuardViolation(
                    "该人员已登记在区内，禁止重复进入", details={"person_id": person_id}
                )
            if self._machine.state == "alarming" and permit["kind"] != "rescue":
                raise GuardViolation(
                    "高温区报警未解除，禁止进入（救援许可除外）",
                    details={"active_alarms": sorted(self._active_alarm_ids())},
                )
            entry_id = "E-" + uuid.uuid4().hex[:12]
            self._occupants[person_id] = {
                "entry_id": entry_id,
                "person_id": person_id,
                "permit_id": permit_id,
                "permit_kind": permit["kind"],
                "approved_by": permit["approved_by"],
                "entered_by": actor,
                "entered_at": self.clock.timestamp_iso(),
                "entered_epoch": now,
                "max_dwell_seconds": float(permit["max_dwell_seconds"]),
            }
            self._entries_total += 1
            record = self._persist(reason="enter")
            self._append_event(
                "entry",
                {
                    "entry_id": entry_id,
                    "person_id": person_id,
                    "permit_id": permit_id,
                    "approved_by": permit["approved_by"],
                    "entered_by": actor,
                    "entered_at": self._occupants[person_id]["entered_at"],
                    "max_dwell_seconds": self._occupants[person_id]["max_dwell_seconds"],
                },
            )
            trace.attach(record).note("entry_id", entry_id).note("permit_id", permit_id)
            return self.status()

    def exit(
        self,
        actor: str,
        *,
        person_id: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "exit",
            f"safety/person/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            occupant = self._occupants.get(person_id)
            if occupant is None:
                raise NotFoundError("该人员未登记在区内", details={"person_id": person_id})
            dwell = self.clock.timestamp() - float(occupant["entered_epoch"])
            overdue = dwell > float(occupant["max_dwell_seconds"])
            del self._occupants[person_id]
            self._exits_total += 1
            record = self._persist(reason="exit")
            self._append_event(
                "exit",
                {
                    "entry_id": occupant["entry_id"],
                    "person_id": person_id,
                    "exited_by": actor,
                    "exited_at": self.clock.timestamp_iso(),
                    "dwell_seconds": round(dwell, 3),
                    "overdue": overdue,
                },
            )
            trace.attach(record).note("dwell_seconds", round(dwell, 3)).note("overdue", overdue)
            return self.status()

    # ------------------------------------------------------------------ 报警
    def sos(
        self,
        actor: str,
        *,
        person_id: str,
        location: str = "",
        message: str = "",
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "sos",
            f"safety/person/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            if not person_id:
                raise ValidationError("求助必须指明人员")
            details: dict[str, Any] = {"registered": person_id in self._occupants}
            if location:
                details["location"] = location
            if message:
                details["message"] = message
            alarm, created = self._raise_alarm("sos", person_id, MAIN_ZONE, details, actor)
            trace.note("alarm_id", alarm["alarm_id"]).note("created", created).note(
                "registered", details["registered"]
            )
            return dict(alarm)

    def intrusion(
        self,
        actor: str,
        *,
        person_id: str,
        zone: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "intrusion",
            f"safety/zone/{zone}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            if zone not in self.forbidden_zones():
                raise ValidationError(
                    "未知的禁区", details={"zone": zone, "known": list(self.forbidden_zones())}
                )
            alarm, created = self._raise_alarm("intrusion", person_id, zone, {}, actor)
            trace.note("alarm_id", alarm["alarm_id"]).note("created", created)
            return dict(alarm)

    def sweep(
        self,
        actor: str,
        *,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "sweep",
            "safety",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            now = self.clock.timestamp()
            overdue: list[str] = []
            raised: list[str] = []
            for person_id, occupant in sorted(self._occupants.items()):
                elapsed = now - float(occupant["entered_epoch"])
                limit = float(occupant["max_dwell_seconds"])
                if elapsed <= limit:
                    continue
                overdue.append(person_id)
                alarm, created = self._raise_alarm(
                    "overstay",
                    person_id,
                    MAIN_ZONE,
                    {"elapsed_seconds": round(elapsed, 3), "max_dwell_seconds": limit},
                    actor,
                )
                if created:
                    raised.append(alarm["alarm_id"])
            trace.note("overdue", list(overdue)).note("raised", list(raised))
            return {
                "state": self._machine.state,
                "checked": len(self._occupants),
                "overdue": overdue,
                "raised_alarms": raised,
                "active_alarm_count": len(self._active_alarm_ids()),
            }

    def acknowledge(
        self,
        actor: str,
        *,
        alarm_id: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "acknowledge",
            f"safety/alarm/{alarm_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            alarm = self._require_alarm(alarm_id)
            if alarm["status"] != "active":
                raise GuardViolation("报警不在待确认状态", details={"status": alarm["status"]})
            alarm["status"] = "acknowledged"
            alarm["ack_by"] = actor
            alarm["ack_at"] = self.clock.timestamp_iso()
            record = self._persist(reason="acknowledge")
            self._append_event(
                "alarm-acknowledged",
                {"alarm_id": alarm_id, "alarm_kind": alarm["kind"], "ack_by": actor},
            )
            trace.attach(record)
            return dict(alarm)

    def resolve(
        self,
        actor: str,
        *,
        alarm_id: str,
        note: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        actor = ensure_actor(actor)
        with self.action(
            "resolve",
            f"safety/alarm/{alarm_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            alarm = self._require_alarm(alarm_id)
            if alarm["status"] not in ALARM_ACTIVE:
                raise GuardViolation("报警已解除，无需重复处理", details={"status": alarm["status"]})
            if not note:
                raise GuardViolation("解除报警必须填写处理说明")
            all_clear = not [aid for aid in self._active_alarm_ids() if aid != alarm_id]
            # 联动先行：恢复常态的广播/门禁失败时，报警保持未解除，可重试。
            linkage = self._restore_normal(actor) if all_clear else None
            alarm["status"] = "resolved"
            alarm["resolve_by"] = actor
            alarm["resolve_note"] = note
            alarm["resolved_at"] = self.clock.timestamp_iso()
            if all_clear:
                self._machine.to("watching", actor, "全部报警已解除")
            record = self._persist(reason="resolve")
            self._append_event(
                "alarm-resolved",
                {
                    "alarm_id": alarm_id,
                    "alarm_kind": alarm["kind"],
                    "resolve_by": actor,
                    "note": note,
                    "all_clear": self._machine.state == "watching",
                },
            )
            trace.attach(record).note("note", note).note("all_clear", all_clear)
            result = dict(alarm)
            result["watch_state"] = self._machine.state
            if linkage is not None:
                result["linkage"] = linkage
            return result

    # ------------------------------------------------------------------ 查询
    @property
    def state(self) -> str:
        return self._machine.state

    def forbidden_zones(self) -> tuple[str, ...]:
        return tuple(
            zone
            for zone in (part.strip() for part in self.settings.safety_forbidden_zones.split(","))
            if zone
        )

    def permits(self, *, include_revoked: bool = False) -> list[Mapping[str, Any]]:
        result: list[Mapping[str, Any]] = []
        for key in self.store.list_keys(self.key("permit")):
            record = self.store.get(key)
            if record is None:
                continue
            payload = dict(record.payload)
            if payload.get("revoked") and not include_revoked:
                continue
            result.append(payload)
        return sorted(result, key=lambda item: str(item.get("issued_at", "")))

    def events(self, *, limit: int = 50) -> list[Mapping[str, Any]]:
        return [dict(entry.payload) for entry in self.store.read_stream(EVENTS_STREAM, limit=limit)]

    def status(self) -> Mapping[str, Any]:
        now = self.clock.timestamp()
        occupants: list[dict[str, Any]] = []
        for occupant in self._occupants.values():
            elapsed = now - float(occupant["entered_epoch"])
            limit = float(occupant["max_dwell_seconds"])
            occupants.append(
                {
                    **occupant,
                    "elapsed_seconds": round(elapsed, 3),
                    "remaining_seconds": round(max(0.0, limit - elapsed), 3),
                    "overdue": elapsed > limit,
                }
            )
        occupants.sort(key=lambda item: str(item["entered_at"]))
        active = sorted(
            (dict(alarm) for alarm in self._alarms.values() if alarm["status"] in ALARM_ACTIVE),
            key=lambda item: str(item["raised_at"]),
        )
        return {
            "state": self._machine.state,
            "occupant_count": len(occupants),
            "occupants": occupants,
            "active_alarm_count": len(active),
            "active_alarms": active,
            "access_modes": self._access.modes(),
            "forbidden_zones": list(self.forbidden_zones()),
            "counters": {
                "entries": self._entries_total,
                "exits": self._exits_total,
                "alarms_raised": self._alarms_raised_total,
            },
            "default_max_dwell_seconds": self.settings.safety_default_max_dwell_seconds,
            "max_dwell_cap_seconds": self.settings.safety_max_dwell_cap_seconds,
            "history": list(self._machine.history),
        }

    # ------------------------------------------------------------------ 内部
    def _raise_alarm(
        self,
        kind: str,
        person_id: str,
        zone: str,
        details: Mapping[str, Any],
        actor: str,
    ) -> tuple[dict[str, Any], bool]:
        for alarm in self._alarms.values():
            if (
                alarm["status"] in ALARM_ACTIVE
                and alarm["kind"] == kind
                and alarm["person_id"] == person_id
                and alarm["zone"] == zone
            ):
                alarm["reports"] = int(alarm.get("reports", 1)) + 1
                alarm["last_reported_at"] = self.clock.timestamp_iso()
                self._persist(reason="alarm-reported")
                self._append_event(
                    "alarm-reported",
                    {
                        "alarm_id": alarm["alarm_id"],
                        "alarm_kind": kind,
                        "person_id": person_id,
                        "zone": zone,
                        "reports": alarm["reports"],
                    },
                )
                return alarm, False
        alarm: dict[str, Any] = {
            "alarm_id": "A-" + uuid.uuid4().hex[:12],
            "kind": kind,
            "person_id": person_id,
            "zone": zone,
            "status": "active",
            "raised_at": self.clock.timestamp_iso(),
            "raised_epoch": self.clock.timestamp(),
            "raised_by": actor,
            "reports": 1,
            "ack_by": None,
            "ack_at": None,
            "resolve_by": None,
            "resolve_note": None,
            "resolved_at": None,
            "details": dict(details),
        }
        # 联动先行：广播/门禁失败时报警不落盘，由上报方重试，绝不留下无声报警。
        alarm["linkage"] = self._linkage_for(alarm, actor)
        if self._machine.state == "watching":
            self._machine.to("alarming", actor, f"{kind} 报警")
        self._alarms[alarm["alarm_id"]] = alarm
        self._alarms_raised_total += 1
        self._persist(reason="alarm-raised")
        self._append_event(
            "alarm-raised",
            {
                "alarm_id": alarm["alarm_id"],
                "alarm_kind": kind,
                "person_id": person_id,
                "zone": zone,
                "linkage": alarm["linkage"],
            },
        )
        return alarm, True

    def _linkage_for(self, alarm: Mapping[str, Any], actor: str) -> Mapping[str, Any]:
        kind = alarm["kind"]
        person_id = alarm["person_id"]
        receipts: dict[str, Any] = {}
        if kind == "sos":
            receipts["broadcast"] = dict(
                self._broadcast.announce(
                    f"高温区紧急求助：{person_id} 触发求助按钮，请立即组织救援。",
                    zone=MAIN_ZONE,
                    level="emergency",
                    actor=actor,
                )
            )
            receipts["access"] = dict(
                self._access.set_mode(MAIN_ZONE, "evacuate", reason="sos 求助报警", actor=actor)
            )
        elif kind == "intrusion":
            zone = str(alarm["zone"])
            receipts["broadcast"] = dict(
                self._broadcast.announce(
                    f"禁区闯入报警：{person_id} 进入 {zone}，请立即撤离并核查。",
                    zone=zone,
                    level="warning",
                    actor=actor,
                )
            )
            receipts["access"] = dict(
                self._access.set_mode(zone, "lockdown", reason="禁区闯入报警", actor=actor)
            )
        else:  # overstay
            receipts["broadcast"] = dict(
                self._broadcast.announce(
                    f"高温区超时滞留：{person_id} 已超过许可停留时长，请立即撤离。",
                    zone=MAIN_ZONE,
                    level="warning",
                    actor=actor,
                )
            )
        return receipts

    def _restore_normal(self, actor: str) -> Mapping[str, Any]:
        receipts: dict[str, Any] = {"access": []}
        for zone, mode in sorted(self._access.modes().items()):
            if mode != "normal":
                receipts["access"].append(
                    dict(self._access.set_mode(zone, "normal", reason="报警全部解除，恢复常态", actor=actor))
                )
        receipts["broadcast"] = dict(
            self._broadcast.announce(
                "高温区安全报警已全部解除，区域恢复常态。",
                zone=MAIN_ZONE,
                level="info",
                actor=actor,
            )
        )
        return receipts

    def _require_permit(self, permit_id: str) -> dict[str, Any]:
        record = self.store.get(self.key("permit", permit_id))
        if record is None:
            raise NotFoundError("许可不存在", details={"permit_id": permit_id})
        return dict(record.payload)

    def _require_alarm(self, alarm_id: str) -> dict[str, Any]:
        alarm = self._alarms.get(alarm_id)
        if alarm is None:
            raise NotFoundError("报警不存在", details={"alarm_id": alarm_id})
        return alarm

    def _active_alarm_ids(self) -> list[str]:
        return [
            alarm_id for alarm_id, alarm in self._alarms.items() if alarm["status"] in ALARM_ACTIVE
        ]

    def _persist(self, *, reason: str) -> Any:
        payload = {
            "state": self._machine.state,
            "reason": reason,
            "written_epoch": self.clock.timestamp(),
            "written_at": self.clock.timestamp_iso(),
            "occupants": {pid: dict(occupant) for pid, occupant in self._occupants.items()},
            "alarms": {aid: dict(alarm) for aid, alarm in self._alarms.items()},
            "entries_total": self._entries_total,
            "exits_total": self._exits_total,
            "alarms_raised_total": self._alarms_raised_total,
            "history": list(self._machine.history),
        }
        record = self.persist_state(payload)
        self._refresh_gauges()
        return record

    def _append_event(self, kind: str, payload: Mapping[str, Any]) -> None:
        event = {"kind": kind, "at": self.clock.timestamp_iso()}
        event.update(payload)
        self.store.append(EVENTS_STREAM, event)

    def _refresh_gauges(self) -> None:
        self.metrics.observe("safety.occupants", float(len(self._occupants)))
        self.metrics.observe("safety.active_alarms", float(len(self._active_alarm_ids())))


__all__ = [
    "PersonnelSafety",
    "STATES",
    "TRANSITIONS",
    "PERMIT_KINDS",
    "ALARM_KINDS",
    "ALARM_ACTIVE",
    "MAIN_ZONE",
    "EVENTS_STREAM",
]
