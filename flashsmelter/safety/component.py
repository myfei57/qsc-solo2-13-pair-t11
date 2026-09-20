"""高温区人员安全组件。

门口挂牌子、靠自觉登记的做法下，「里面还有几个人、谁进去多久了」没有权威答案，
中暑无人知晓的事故正是由此而来。本组件把高温区人员管理收进控制平台：

* 进入必须先有审批：谁批的、批了多久、是否含禁区，批条全部落盘；
* 凭批条刷卡进出，区内人数与每人剩余时长实时可查，重启不丢；
* 控制系统每轮扫描调用 ``sweep`` 检查超时滞留；定位事件经 ``report_position``
  判定禁区闯入；求助按钮走 ``sos``——三类警情先落盘，再联动广播与门禁；
* 报警未解除前，对应区域拒绝新的进入（软件联锁与门禁指令双保险）；
* 所有动作经审计流水留痕，进出、警情、联动另有独立 journal 供回溯。
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping

from ..component import Component, ensure_actor
from ..errors import GuardViolation, NotFoundError, ValidationError
from ..runtime import RuntimeContext, iso_from_epoch
from ..store import Record
from .linkage import AccessControlPort, BroadcastPort
from .models import (
    ALARM_SEVERITIES,
    PLANT_ZONE,
    ZONES,
    AlarmRecord,
    PassRecord,
    SessionRecord,
    is_restricted,
    require_token,
    require_zone,
    zone_label,
)

PRESENCE_STREAM = "safety/presence"
ALARM_STREAM = "safety/alarms"


class PersonnelSafety(Component):
    """高温区人员安全：审批、进出登记、超时/闯入/求助报警与联动。"""

    name = "safety"

    def __init__(self, ctx: RuntimeContext, *, broadcast: BroadcastPort, access: AccessControlPort) -> None:
        super().__init__(ctx)
        self._broadcast = broadcast
        self._access = access
        self._personnel: dict[str, dict[str, Any]] = {}
        self._passes: dict[str, PassRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._alarms: dict[str, AlarmRecord] = {}
        self._last_sweep_at: str | None = None
        restored = self.restore()
        if restored is not None:
            self._last_sweep_at = restored.get("last_sweep_at")
        self._restore_index()
        self._refresh_gauges()

    # ------------------------------------------------------------------ 人员登记
    def register_person(
        self,
        actor: str,
        *,
        person_id: str,
        name: str,
        role: str,
        quals: str = "",
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "register_person",
            f"safety/personnel/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            existing = self._personnel.get(person_id)
            if existing is not None and existing.get("active", False):
                raise GuardViolation("人员已登记", details={"person_id": person_id})
            if not name or not role:
                raise ValidationError("姓名与岗位必须填写", details={"person_id": person_id})
            record = {
                "person_id": person_id,
                "name": name,
                "role": role,
                "quals": quals,
                "active": True,
                "registered_by": actor,
                "registered_at": self.clock.timestamp_iso(),
            }
            stored = self._write_doc("personnel", person_id, record)
            self._personnel[person_id] = record
            self._persist_state("register_person")
            trace.attach(stored).note("person_id", person_id).note("name", name)
            return dict(record)

    def deregister_person(
        self,
        actor: str,
        *,
        person_id: str,
        note: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "deregister_person",
            f"safety/personnel/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            record = self._require_person(person_id)
            if person_id in self._sessions:
                raise GuardViolation(
                    "人员仍在区内，禁止注销",
                    details={"person_id": person_id, "zone": self._sessions[person_id].zone},
                )
            if not note:
                raise ValidationError("注销必须填写原因", details={"person_id": person_id})
            record = dict(record)
            record.update(
                {
                    "active": False,
                    "deregistered_by": actor,
                    "deregistered_at": self.clock.timestamp_iso(),
                    "deregister_note": note,
                }
            )
            stored = self._write_doc("personnel", person_id, record)
            self._personnel[person_id] = record
            self._persist_state("deregister_person")
            trace.attach(stored).note("person_id", person_id).note("note", note)
            return dict(record)

    # ------------------------------------------------------------------ 进入审批
    def approve_entry(
        self,
        actor: str,
        *,
        person_id: str,
        zone: str,
        reason: str,
        max_dwell_seconds: float | None = None,
        valid_seconds: float | None = None,
        allow_restricted: bool = False,
        pass_id: str | None = None,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "approve_entry",
            f"safety/pass/{zone}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            self._require_person(person_id)
            require_zone(zone)
            if is_restricted(zone) and not allow_restricted:
                raise GuardViolation(
                    "禁区进入必须在审批中显式授权",
                    details={"zone": zone, "zone_label": zone_label(zone)},
                )
            if not is_restricted(zone) and allow_restricted:
                raise ValidationError("一般区域无需禁区授权", details={"zone": zone})
            dwell = (
                self.settings.safety_default_max_dwell_seconds
                if max_dwell_seconds is None
                else float(max_dwell_seconds)
            )
            if not 0 < dwell <= self.settings.safety_max_dwell_seconds:
                raise GuardViolation(
                    "批准滞留时长超出上限",
                    details={"requested": dwell, "max": self.settings.safety_max_dwell_seconds},
                )
            valid = self.settings.safety_pass_valid_seconds if valid_seconds is None else float(valid_seconds)
            if not 0 < valid <= self.settings.safety_pass_valid_seconds:
                raise GuardViolation(
                    "批条有效期超出上限",
                    details={"requested": valid, "max": self.settings.safety_pass_valid_seconds},
                )
            if not reason:
                raise ValidationError("审批必须填写事由", details={"person_id": person_id, "zone": zone})
            pass_id = require_token(pass_id, "批条") if pass_id else "PS-" + uuid.uuid4().hex[:12]
            if pass_id in self._passes:
                raise GuardViolation("批条号已存在", details={"pass_id": pass_id})
            now = self.clock.timestamp()
            record = PassRecord(
                pass_id=pass_id,
                person_id=person_id,
                zone=zone,
                approver=actor,
                reason=reason,
                approved_at=self.clock.timestamp_iso(),
                valid_until_epoch=now + valid,
                valid_until=iso_from_epoch(now + valid),
                max_dwell_seconds=dwell,
                allow_restricted=allow_restricted,
            )
            stored = self._write_doc("pass", pass_id, record.to_dict())
            self._passes[pass_id] = record
            self._persist_state("approve_entry")
            trace.attach(stored).note("pass_id", pass_id).note("person_id", person_id).note("zone", zone)
            return record.to_dict()

    def revoke_pass(
        self,
        actor: str,
        *,
        pass_id: str,
        note: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        pass_id = require_token(pass_id, "批条")
        actor = ensure_actor(actor)
        with self.action(
            "revoke_pass",
            f"safety/pass/{pass_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            record = self._require_pass(pass_id)
            if record.status != "active":
                raise GuardViolation("批条已作废，无需重复操作", details={"pass_id": pass_id})
            if not note:
                raise ValidationError("作废批条必须填写原因", details={"pass_id": pass_id})
            record.status = "revoked"
            record.revoked_at = self.clock.timestamp_iso()
            record.revoked_by = actor
            record.revoke_note = note
            stored = self._write_doc("pass", pass_id, record.to_dict())
            self._persist_state("revoke_pass")
            trace.attach(stored).note("pass_id", pass_id).note("note", note)
            return record.to_dict()

    # ------------------------------------------------------------------ 进出登记
    def enter(
        self,
        actor: str,
        *,
        person_id: str,
        pass_id: str,
        zone: str,
        gate: str = "gate-1",
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        person_id = require_token(person_id, "人员")
        pass_id = require_token(pass_id, "批条")
        actor = ensure_actor(actor)
        with self.action(
            "enter",
            f"safety/zone/{zone}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            self._require_person(person_id)
            require_zone(zone)
            if person_id in self._sessions:
                raise GuardViolation(
                    "该人员已有在区记录，禁止重复进入",
                    details={"person_id": person_id, "zone": self._sessions[person_id].zone},
                )
            if self._zone_suspended(zone):
                raise GuardViolation(
                    "区域有未解除报警，门禁不放行",
                    details={"zone": zone, "zone_label": zone_label(zone)},
                )
            pass_record = self._require_pass(pass_id)
            now = self.clock.timestamp()
            if pass_record.status != "active":
                raise GuardViolation("批条已作废", details={"pass_id": pass_id})
            if pass_record.person_id != person_id:
                raise GuardViolation(
                    "批条与人员不符",
                    details={"pass_id": pass_id, "pass_person": pass_record.person_id, "person_id": person_id},
                )
            if pass_record.zone != zone:
                raise GuardViolation(
                    "批条区域不符",
                    details={"pass_id": pass_id, "pass_zone": pass_record.zone, "zone": zone},
                )
            if now > pass_record.valid_until_epoch:
                raise GuardViolation(
                    "批条已过期",
                    details={"pass_id": pass_id, "valid_until": pass_record.valid_until},
                )
            if is_restricted(zone) and not pass_record.allow_restricted:
                raise GuardViolation(
                    "禁区进入未获授权",
                    details={"zone": zone, "zone_label": zone_label(zone), "pass_id": pass_id},
                )
            session = SessionRecord(
                session_id="SS-" + uuid.uuid4().hex[:12],
                person_id=person_id,
                zone=zone,
                gate=gate,
                pass_id=pass_id,
                approver=pass_record.approver,
                entered_at=self.clock.timestamp_iso(),
                entered_epoch=now,
                deadline_epoch=now + pass_record.max_dwell_seconds,
                max_dwell_seconds=pass_record.max_dwell_seconds,
            )
            stored = self._write_doc("session", person_id, session.to_dict())
            self._sessions[person_id] = session
            self.store.append(PRESENCE_STREAM, {"event": "enter", **session.to_dict()})
            self._persist_state("enter")
            trace.attach(stored).note("person_id", person_id).note("zone", zone).note("pass_id", pass_id)
            return {"session": session.to_dict(), "zone_presence": self._zone_presence(zone)}

    def exit(
        self,
        actor: str,
        *,
        person_id: str,
        gate: str = "gate-1",
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "exit",
            f"safety/personnel/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            session = self._sessions.get(person_id)
            if session is None:
                raise GuardViolation("该人员无在区记录", details={"person_id": person_id})
            now = self.clock.timestamp()
            session.status = "exited"
            session.exited_epoch = now
            session.exited_at = self.clock.timestamp_iso()
            session.dwell_seconds = round(now - session.entered_epoch, 3)
            session.overdue = now > session.deadline_epoch
            stored = self._write_doc("session", person_id, session.to_dict())
            del self._sessions[person_id]
            self.store.append(PRESENCE_STREAM, {"event": "exit", "gate": gate, **session.to_dict()})
            self._persist_state("exit")
            trace.attach(stored).note("person_id", person_id).note("overdue", session.overdue)
            return {"session": session.to_dict(), "zone_presence": self._zone_presence(session.zone)}

    # ------------------------------------------------------------------ 警情输入
    def report_position(
        self,
        actor: str,
        *,
        person_id: str,
        zone: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        """定位事件：人在某区域却没有覆盖该区域的有效的在场记录，即判闯入。"""

        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "report_position",
            f"safety/zone/{zone}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            require_zone(zone)
            session = self._sessions.get(person_id)
            if session is not None and session.zone == zone:
                trace.note("person_id", person_id).note("zone", zone).note("intrusion", False)
                return {"intrusion": False, "person_id": person_id, "zone": zone}
            existing = self._find_unresolved_alarm("intrusion", person_id=person_id, zone=zone)
            if existing is not None:
                trace.note("person_id", person_id).note("zone", zone).note("deduplicated", True)
                return {
                    "intrusion": True,
                    "deduplicated": True,
                    "alarm": existing.to_dict(),
                }
            person_known = person_id in self._personnel and bool(self._personnel[person_id].get("active"))
            summary = (
                f"{self._person_label(person_id)} 未经授权出现在{zone_label(zone)}"
                + ("（禁区）" if is_restricted(zone) else "")
            )
            alarm = self._raise_alarm(
                "intrusion",
                actor=actor,
                person_id=person_id,
                zone=zone,
                summary=summary,
                details={
                    "person_known": person_known,
                    "restricted": is_restricted(zone),
                    "registered_zone": session.zone if session is not None else None,
                },
            )
            trace.note("person_id", person_id).note("zone", zone).note("alarm_id", alarm.alarm_id)
            return {"intrusion": True, "deduplicated": False, "alarm": alarm.to_dict()}

    def sos(
        self,
        actor: str,
        *,
        person_id: str,
        zone: str | None = None,
        note: str = "",
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        """求助按钮：无论人员是否登记都必须立即出警，绝不因校验拒绝。"""

        person_id = require_token(person_id, "人员")
        actor = ensure_actor(actor)
        with self.action(
            "sos",
            f"safety/personnel/{person_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            session = self._sessions.get(person_id)
            if zone is not None:
                require_zone(zone)
                alarm_zone = zone
            elif session is not None:
                alarm_zone = session.zone
            else:
                alarm_zone = PLANT_ZONE
            person_known = person_id in self._personnel and bool(self._personnel[person_id].get("active"))
            summary = f"{self._person_label(person_id)} 在{zone_label(alarm_zone) if alarm_zone != PLANT_ZONE else '全厂'}发出求助"
            alarm = self._raise_alarm(
                "sos",
                actor=actor,
                person_id=person_id,
                zone=alarm_zone,
                summary=summary,
                details={"person_known": person_known, "note": note},
            )
            trace.note("person_id", person_id).note("zone", alarm_zone).note("alarm_id", alarm.alarm_id)
            return {"alarm": alarm.to_dict()}

    def sweep(
        self,
        actor: str,
        *,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        """控制系统每轮扫描调用：检查在场人员是否超过批准滞留时长。"""

        actor = ensure_actor(actor)
        with self.action(
            "sweep",
            "safety",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            now = self.clock.timestamp()
            grace = self.settings.safety_overstay_grace_seconds
            raised: list[str] = []
            overdue: list[str] = []
            for session in list(self._sessions.values()):
                if now <= session.deadline_epoch + grace:
                    continue
                overdue.append(session.person_id)
                if self._find_unresolved_alarm("overstay", session_id=session.session_id) is not None:
                    continue
                summary = (
                    f"{self._person_label(session.person_id)} 在{zone_label(session.zone)}"
                    f"滞留超过批准时长（{session.max_dwell_seconds:.0f} 秒）"
                )
                alarm = self._raise_alarm(
                    "overstay",
                    actor=actor,
                    person_id=session.person_id,
                    zone=session.zone,
                    summary=summary,
                    details={
                        "session_id": session.session_id,
                        "entered_at": session.entered_at,
                        "deadline_at": iso_from_epoch(session.deadline_epoch),
                        "overdue_seconds": round(now - session.deadline_epoch, 3),
                    },
                )
                raised.append(alarm.alarm_id)
            self._last_sweep_at = self.clock.timestamp_iso()
            self._persist_state("sweep")
            trace.note("checked", len(self._sessions)).note("raised", len(raised))
            return {"checked": len(self._sessions), "overdue": overdue, "raised": raised}

    # ------------------------------------------------------------------ 警情处置
    def acknowledge(
        self,
        actor: str,
        *,
        alarm_id: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        alarm_id = require_token(alarm_id, "报警")
        actor = ensure_actor(actor)
        with self.action(
            "acknowledge",
            f"safety/alarm/{alarm_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            alarm = self._require_alarm(alarm_id)
            if alarm.status != "active":
                raise GuardViolation(
                    "只有待处理报警可以确认",
                    details={"alarm_id": alarm_id, "status": alarm.status},
                )
            alarm.status = "acknowledged"
            alarm.acknowledged_at = self.clock.timestamp_iso()
            alarm.acknowledged_by = actor
            stored = self._write_doc("alarm", alarm_id, alarm.to_dict())
            self.store.append(ALARM_STREAM, {"event": "acknowledged", **alarm.to_dict()})
            self._persist_state("acknowledge")
            trace.attach(stored).note("alarm_id", alarm_id)
            return {"alarm": alarm.to_dict(), "zone_entry_suspended": self._zone_suspended(alarm.zone)}

    def resolve(
        self,
        actor: str,
        *,
        alarm_id: str,
        note: str,
        correlation_id: str | None = None,
        expected_generation: int | None = None,
    ) -> Mapping[str, Any]:
        alarm_id = require_token(alarm_id, "报警")
        actor = ensure_actor(actor)
        with self.action(
            "resolve",
            f"safety/alarm/{alarm_id}",
            actor,
            correlation_id=correlation_id,
            expected_generation=expected_generation,
        ) as trace:
            alarm = self._require_alarm(alarm_id)
            if alarm.status == "resolved":
                raise GuardViolation("报警已解除，无需重复操作", details={"alarm_id": alarm_id})
            if not note:
                raise ValidationError("解除报警必须填写处理结论", details={"alarm_id": alarm_id})
            alarm.status = "resolved"
            alarm.resolved_at = self.clock.timestamp_iso()
            alarm.resolved_by = actor
            alarm.resolve_note = note
            stored = self._write_doc("alarm", alarm_id, alarm.to_dict())
            self.store.append(ALARM_STREAM, {"event": "resolved", **alarm.to_dict()})
            self._persist_state("resolve")
            trace.attach(stored).note("alarm_id", alarm_id).note("note", note)
            return {"alarm": alarm.to_dict(), "zone_entry_suspended": self._zone_suspended(alarm.zone)}

    # ------------------------------------------------------------------ 查询
    def presence_report(self) -> Mapping[str, Any]:
        """「里面还有几个人」的权威答案：按区域列出在场人员与剩余时长。"""

        now = self.clock.timestamp()
        zones: dict[str, list[Mapping[str, Any]]] = {}
        for session in self._sessions.values():
            zones.setdefault(session.zone, []).append(self._session_view(session, now))
        return {
            "present_total": len(self._sessions),
            "zones": {zone: persons for zone, persons in sorted(zones.items())},
        }

    def alarm_report(self, *, active_only: bool = True, limit: int = 50) -> list[Mapping[str, Any]]:
        alarms = [a for a in self._alarms.values() if not active_only or a.status != "resolved"]
        alarms.sort(key=lambda alarm: alarm.raised_epoch, reverse=True)
        return [alarm.to_dict() for alarm in alarms[:limit]]

    def personnel_report(self) -> list[Mapping[str, Any]]:
        return [dict(record) for _, record in sorted(self._personnel.items())]

    def presence_events(self, *, limit: int = 50) -> list[Mapping[str, Any]]:
        return [dict(entry.payload) for entry in self.store.read_stream(PRESENCE_STREAM, limit=limit)]

    def alarm_events(self, *, limit: int = 50) -> list[Mapping[str, Any]]:
        return [dict(entry.payload) for entry in self.store.read_stream(ALARM_STREAM, limit=limit)]

    def is_zone_suspended(self, zone: str) -> bool:
        return self._zone_suspended(zone)

    def status(self) -> Mapping[str, Any]:
        now = self.clock.timestamp()
        zones: dict[str, Any] = {}
        for zone, info in ZONES.items():
            persons = [
                self._session_view(session, now)
                for session in self._sessions.values()
                if session.zone == zone
            ]
            unresolved = [a for a in self._alarms.values() if a.zone == zone and a.status != "resolved"]
            zones[zone] = {
                "label": info["label"],
                "level": info["level"],
                "present": len(persons),
                "persons": persons,
                "entry_suspended": bool(unresolved),
                "alarms_unresolved": len(unresolved),
            }
        unresolved_all = [a for a in self._alarms.values() if a.status != "resolved"]
        unresolved_all.sort(key=lambda alarm: alarm.raised_epoch)
        return {
            "state": self._posture(),
            "present_total": len(self._sessions),
            "zones": zones,
            "active_alarms": [alarm.to_dict() for alarm in unresolved_all],
            "counts": {
                "personnel": sum(1 for record in self._personnel.values() if record.get("active")),
                "passes_active": sum(1 for record in self._passes.values() if record.status == "active"),
                "sessions_active": len(self._sessions),
                "alarms_unresolved": len(unresolved_all),
                "alarms_total": len(self._alarms),
            },
            "last_sweep_at": self._last_sweep_at,
        }

    # ------------------------------------------------------------------ 内部：报警与联动
    def _raise_alarm(
        self,
        kind: str,
        *,
        actor: str,
        person_id: str,
        zone: str,
        summary: str,
        details: Mapping[str, Any],
    ) -> AlarmRecord:
        """警情先落盘、再联动：联动失败不吞报警，错误记入警情与指标。"""

        now = self.clock.timestamp()
        alarm = AlarmRecord(
            alarm_id="AL-" + uuid.uuid4().hex[:12],
            kind=kind,
            severity=ALARM_SEVERITIES[kind],
            person_id=person_id,
            zone=zone,
            summary=summary,
            raised_by=actor,
            raised_at=self.clock.timestamp_iso(),
            raised_epoch=now,
            details=dict(details),
        )
        self._write_doc("alarm", alarm.alarm_id, alarm.to_dict())
        self._alarms[alarm.alarm_id] = alarm
        self.store.append(ALARM_STREAM, {"event": "raised", **alarm.to_dict()})
        alarm.linkage = self._dispatch_linkage(alarm)
        self._write_doc("alarm", alarm.alarm_id, alarm.to_dict())
        self.metrics.inc(f"safety.alarm.{kind}")
        return alarm

    def _dispatch_linkage(self, alarm: AlarmRecord) -> list[dict[str, Any]]:
        person = self._person_label(alarm.person_id)
        zone = zone_label(alarm.zone) if alarm.zone != PLANT_ZONE else "全厂"
        messages = {
            "sos": f"紧急求助：{person}在{zone}发出求助信号，请附近人员立即支援，疏散通道已解锁。",
            "overstay": f"超时滞留：{person}在{zone}滞留超过批准时长，请立即撤离并到登记处核销。",
            "intrusion": f"禁区报警：{person}未经授权出现在{zone}，请立即离开，安保人员请前往处置。",
        }
        access_commands = {
            "sos": ("release_evacuation", "suspend_entry"),
            "overstay": ("suspend_entry",),
            "intrusion": ("lockdown", "suspend_entry"),
        }
        receipts: list[dict[str, Any]] = []
        try:
            receipt = self._broadcast.announce(
                alarm.zone, messages[alarm.kind], alarm_id=alarm.alarm_id, kind=alarm.kind
            )
            receipts.append({"channel": "broadcast", "ok": True, "receipt": dict(receipt)})
        except Exception as exc:  # 联动失败绝不吞掉报警本身
            self.metrics.inc("safety.linkage.failed")
            receipts.append({"channel": "broadcast", "ok": False, "error": str(exc)})
        if alarm.zone in ZONES:
            for command in access_commands[alarm.kind]:
                try:
                    receipt = self._access.execute(
                        command, alarm.zone, alarm_id=alarm.alarm_id, reason=alarm.summary
                    )
                    receipts.append({"channel": "access_control", "command": command, "ok": True, "receipt": dict(receipt)})
                except Exception as exc:  # 联动失败绝不吞掉报警本身
                    self.metrics.inc("safety.linkage.failed")
                    receipts.append(
                        {"channel": "access_control", "command": command, "ok": False, "error": str(exc)}
                    )
        return receipts

    # ------------------------------------------------------------------ 内部：状态与索引
    def _restore_index(self) -> None:
        """重启后从落盘文档重建索引：在场人员与未解除报警一个都不丢。"""

        for key in self.store.list_keys(self.key("personnel")):
            record = self.store.get(key)
            if record is not None:
                self._personnel[str(record.payload.get("person_id"))] = dict(record.payload)
        for key in self.store.list_keys(self.key("pass")):
            record = self.store.get(key)
            if record is not None:
                loaded = PassRecord.from_dict(record.payload)
                self._passes[loaded.pass_id] = loaded
        for key in self.store.list_keys(self.key("session")):
            record = self.store.get(key)
            if record is not None:
                loaded = SessionRecord.from_dict(record.payload)
                if loaded.status == "inside":
                    self._sessions[loaded.person_id] = loaded
        for key in self.store.list_keys(self.key("alarm")):
            record = self.store.get(key)
            if record is not None:
                loaded = AlarmRecord.from_dict(record.payload)
                self._alarms[loaded.alarm_id] = loaded

    def _persist_state(self, reason: str) -> Record:
        per_zone = {zone: 0 for zone in ZONES}
        for session in self._sessions.values():
            per_zone[session.zone] = per_zone.get(session.zone, 0) + 1
        payload = {
            "reason": reason,
            "written_epoch": self.clock.timestamp(),
            "written_at": self.clock.timestamp_iso(),
            "present_total": len(self._sessions),
            "per_zone": per_zone,
            "alarms_unresolved": sum(1 for alarm in self._alarms.values() if alarm.status != "resolved"),
            "last_sweep_at": self._last_sweep_at,
        }
        record = self.persist_state(payload)
        self._refresh_gauges()
        return record

    def _write_doc(self, kind: str, identifier: str, payload: Mapping[str, Any]) -> Record:
        return self.store.commit_intent(self.key(kind, identifier), payload)

    def _require_person(self, person_id: str) -> Mapping[str, Any]:
        record = self._personnel.get(person_id)
        if record is None or not record.get("active", False):
            raise NotFoundError("人员未登记或已注销", details={"person_id": person_id})
        return record

    def _require_pass(self, pass_id: str) -> PassRecord:
        record = self._passes.get(pass_id)
        if record is None:
            raise NotFoundError("批条不存在", details={"pass_id": pass_id})
        return record

    def _require_alarm(self, alarm_id: str) -> AlarmRecord:
        alarm = self._alarms.get(alarm_id)
        if alarm is None:
            raise NotFoundError("报警不存在", details={"alarm_id": alarm_id})
        return alarm

    def _find_unresolved_alarm(
        self,
        kind: str,
        *,
        person_id: str | None = None,
        zone: str | None = None,
        session_id: str | None = None,
    ) -> AlarmRecord | None:
        for alarm in self._alarms.values():
            if alarm.kind != kind or alarm.status == "resolved":
                continue
            if person_id is not None and alarm.person_id != person_id:
                continue
            if zone is not None and alarm.zone != zone:
                continue
            if session_id is not None and alarm.details.get("session_id") != session_id:
                continue
            return alarm
        return None

    def _zone_suspended(self, zone: str) -> bool:
        return any(
            alarm.zone == zone and alarm.status != "resolved" for alarm in self._alarms.values()
        )

    def _posture(self) -> str:
        """总体态势：有未解除报警即 alarmed，区内有人即 occupied，否则 clear。"""

        if any(alarm.status != "resolved" for alarm in self._alarms.values()):
            return "alarmed"
        if self._sessions:
            return "occupied"
        return "clear"

    def _zone_presence(self, zone: str) -> Mapping[str, Any]:
        now = self.clock.timestamp()
        persons = [
            self._session_view(session, now)
            for session in self._sessions.values()
            if session.zone == zone
        ]
        return {"zone": zone, "present": len(persons), "persons": persons}

    def _session_view(self, session: SessionRecord, now: float) -> Mapping[str, Any]:
        person = self._personnel.get(session.person_id, {})
        return {
            "person_id": session.person_id,
            "name": person.get("name", session.person_id),
            "zone": session.zone,
            "entered_at": session.entered_at,
            "approver": session.approver,
            "pass_id": session.pass_id,
            "remaining_seconds": round(session.deadline_epoch - now, 3),
            "overdue": now > session.deadline_epoch,
        }

    def _person_label(self, person_id: str) -> str:
        record = self._personnel.get(person_id)
        if record is None:
            return person_id
        return f"{record.get('name', person_id)}（{person_id}）"

    def _refresh_gauges(self) -> None:
        self.metrics.observe("safety.present_total", float(len(self._sessions)))
        self.metrics.observe(
            "safety.alarms_unresolved",
            float(sum(1 for alarm in self._alarms.values() if alarm.status != "resolved")),
        )
        for zone in ZONES:
            self.metrics.observe(
                f"safety.zone.{zone}.present",
                float(sum(1 for session in self._sessions.values() if session.zone == zone)),
            )


__all__ = ["PersonnelSafety", "PRESENCE_STREAM", "ALARM_STREAM"]
