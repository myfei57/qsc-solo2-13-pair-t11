"""高温区人员安全：审批留痕、进出登记、超时/闯入/求助报警与广播门禁联动。"""

from __future__ import annotations

import unittest

from flashsmelter.application import Application
from flashsmelter.errors import GuardViolation, NotFoundError, ValidationError
from flashsmelter.safety.models import ZONES

from .helpers import make_app, make_root


def _register(app, person_id="P-001", name="张三"):
    return app.safety.register_person("safety-officer", person_id=person_id, name=name, role="炉前工")


def _approve(app, person_id="P-001", zone="reactor-floor", **kwargs):
    kwargs.setdefault("reason", "炉前点检")
    return app.safety.approve_entry("shift-lead", person_id=person_id, zone=zone, **kwargs)


def _enter(app, person_id="P-001", zone="reactor-floor", **kwargs):
    approved = _approve(app, person_id, zone, **kwargs)
    return app.safety.enter("gate-controller", person_id=person_id, pass_id=approved["pass_id"], zone=zone)


class PersonnelRegistrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()

    def test_register_and_deregister(self) -> None:
        record = _register(self.app)
        self.assertEqual("张三", record["name"])
        self.assertEqual("safety-officer", record["registered_by"])
        with self.assertRaises(GuardViolation):
            _register(self.app)
        closed = self.app.safety.deregister_person("safety-officer", person_id="P-001", note="离职")
        self.assertFalse(closed["active"])
        with self.assertRaises(NotFoundError):
            self.app.safety.approve_entry("shift-lead", person_id="P-001", zone="reactor-floor", reason="点检")

    def test_deregister_blocked_while_inside(self) -> None:
        _register(self.app)
        _enter(self.app)
        with self.assertRaises(GuardViolation):
            self.app.safety.deregister_person("safety-officer", person_id="P-001", note="调岗")
        self.app.safety.exit("gate-controller", person_id="P-001")
        closed = self.app.safety.deregister_person("safety-officer", person_id="P-001", note="调岗")
        self.assertFalse(closed["active"])


class ApprovalTrailTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def test_approval_records_approver_and_reason(self) -> None:
        approved = _approve(self.app, max_dwell_seconds=900.0)
        self.assertEqual("shift-lead", approved["approver"])
        self.assertEqual("炉前点检", approved["reason"])
        self.assertEqual(900.0, approved["max_dwell_seconds"])
        self.assertTrue(approved["approved_at"])
        audits = self.app.audit_events(action="approve_entry", actor="shift-lead")
        self.assertEqual(1, len(audits))
        self.assertEqual("ok", audits[0]["outcome"])

    def test_dwell_cap_and_reason_required(self) -> None:
        with self.assertRaises(GuardViolation):
            _approve(self.app, max_dwell_seconds=self.app.settings.safety_max_dwell_seconds + 1)
        with self.assertRaises(ValidationError):
            self.app.safety.approve_entry("shift-lead", person_id="P-001", zone="reactor-floor", reason="")

    def test_restricted_zone_needs_explicit_grant(self) -> None:
        with self.assertRaises(GuardViolation):
            _approve(self.app, zone="tapping-aisle")
        with self.assertRaises(ValidationError):
            _approve(self.app, zone="reactor-floor", allow_restricted=True)
        granted = _approve(self.app, zone="tapping-aisle", allow_restricted=True)
        self.assertTrue(granted["allow_restricted"])

    def test_revoke_pass(self) -> None:
        approved = _approve(self.app)
        with self.assertRaises(ValidationError):
            self.app.safety.revoke_pass("shift-lead", pass_id=approved["pass_id"], note="")
        revoked = self.app.safety.revoke_pass("shift-lead", pass_id=approved["pass_id"], note="计划取消")
        self.assertEqual("revoked", revoked["status"])
        with self.assertRaises(GuardViolation):
            self.app.safety.enter(
                "gate-controller", person_id="P-001", pass_id=approved["pass_id"], zone="reactor-floor"
            )


class EntryExitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def test_enter_exit_cycle_and_presence(self) -> None:
        entered = _enter(self.app)
        self.assertEqual(1, entered["zone_presence"]["present"])
        status = self.app.safety.status()
        self.assertEqual(1, status["present_total"])
        person = status["zones"]["reactor-floor"]["persons"][0]
        self.assertEqual("P-001", person["person_id"])
        self.assertEqual("shift-lead", person["approver"])  # 谁批的，区内名单直接可见
        exited = self.app.safety.exit("gate-controller", person_id="P-001")
        self.assertFalse(exited["session"]["overdue"])
        self.assertGreaterEqual(exited["session"]["dwell_seconds"], 0.0)
        self.assertEqual(0, self.app.safety.status()["present_total"])

    def test_presence_journal_keeps_full_trail(self) -> None:
        _enter(self.app)
        self.app.safety.exit("gate-controller", person_id="P-001")
        events = self.app.safety.presence_events()
        self.assertEqual(["enter", "exit"], [event["event"] for event in events])
        self.assertEqual("shift-lead", events[0]["approver"])  # 什么时候进的、谁批的都留痕
        self.assertTrue(events[0]["entered_at"])
        self.assertTrue(events[1]["exited_at"])

    def test_enter_requires_matching_valid_pass(self) -> None:
        with self.assertRaises(NotFoundError):
            self.app.safety.enter("gate-controller", person_id="P-001", pass_id="PS-none", zone="reactor-floor")
        approved = _approve(self.app, zone="settler-deck")
        with self.assertRaises(GuardViolation):  # 批条区域不符
            self.app.safety.enter(
                "gate-controller", person_id="P-001", pass_id=approved["pass_id"], zone="reactor-floor"
            )
        self.app.clock.advance(self.app.settings.safety_pass_valid_seconds + 1)
        with self.assertRaises(GuardViolation):  # 批条已过期
            self.app.safety.enter(
                "gate-controller", person_id="P-001", pass_id=approved["pass_id"], zone="settler-deck"
            )

    def test_duplicate_entry_rejected(self) -> None:
        _enter(self.app)
        approved = _approve(self.app, zone="settler-deck")
        with self.assertRaises(GuardViolation):
            self.app.safety.enter(
                "gate-controller", person_id="P-001", pass_id=approved["pass_id"], zone="settler-deck"
            )

    def test_exit_without_entry_rejected(self) -> None:
        with self.assertRaises(GuardViolation):
            self.app.safety.exit("gate-controller", person_id="P-001")

    def test_unknown_zone_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            _approve(self.app, zone="nowhere")


class OverstayAlarmTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def _overstay_alarm(self):
        _enter(self.app, max_dwell_seconds=60.0)
        self.app.clock.advance(61.0)
        result = self.app.safety.sweep("control-system")
        self.assertEqual(["P-001"], result["overdue"])
        self.assertEqual(1, len(result["raised"]))
        return self.app.safety.alarm_report()[0]

    def test_sweep_raises_overstay_and_dispatches_linkage(self) -> None:
        alarm = self._overstay_alarm()
        self.assertEqual("overstay", alarm["kind"])
        self.assertEqual("major", alarm["severity"])
        channels = {(item["channel"], item.get("command")) for item in alarm["linkage"]}
        self.assertIn(("broadcast", None), channels)
        self.assertIn(("access_control", "suspend_entry"), channels)
        self.assertTrue(all(item["ok"] for item in alarm["linkage"]))
        linkage = self.app.safety.status()["zones"]["reactor-floor"]
        self.assertTrue(linkage["entry_suspended"])

    def test_sweep_deduplicates_active_alarm(self) -> None:
        self._overstay_alarm()
        again = self.app.safety.sweep("control-system")
        self.assertEqual([], again["raised"])
        self.assertEqual(1, self.app.safety.status()["counts"]["alarms_unresolved"])

    def test_sweep_respects_dwell_and_grace(self) -> None:
        _enter(self.app, max_dwell_seconds=60.0)
        self.app.clock.advance(59.0)
        result = self.app.safety.sweep("control-system")
        self.assertEqual([], result["raised"])
        self.assertEqual(0, self.app.safety.status()["counts"]["alarms_unresolved"])

    def test_zone_entry_blocked_until_alarm_resolved(self) -> None:
        alarm = self._overstay_alarm()
        _register(self.app, person_id="P-002", name="李四")
        approved = _approve(self.app, person_id="P-002")
        with self.assertRaises(GuardViolation):
            self.app.safety.enter(
                "gate-controller", person_id="P-002", pass_id=approved["pass_id"], zone="reactor-floor"
            )
        self.app.safety.acknowledge("dispatcher", alarm_id=alarm["alarm_id"])
        with self.assertRaises(GuardViolation):  # 确认不等于解除，区域仍不放行
            self.app.safety.enter(
                "gate-controller", person_id="P-002", pass_id=approved["pass_id"], zone="reactor-floor"
            )
        resolved = self.app.safety.resolve("dispatcher", alarm_id=alarm["alarm_id"], note="人员已撤离，现场确认")
        self.assertFalse(resolved["zone_entry_suspended"])
        entered = self.app.safety.enter(
            "gate-controller", person_id="P-002", pass_id=approved["pass_id"], zone="reactor-floor"
        )
        self.assertEqual(2, entered["zone_presence"]["present"])


class IntrusionAlarmTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def test_registered_presence_is_not_intrusion(self) -> None:
        _enter(self.app)
        result = self.app.safety.report_position("positioning", person_id="P-001", zone="reactor-floor")
        self.assertFalse(result["intrusion"])

    def test_unregistered_presence_raises_intrusion(self) -> None:
        result = self.app.safety.report_position("positioning", person_id="P-001", zone="tapping-aisle")
        self.assertTrue(result["intrusion"])
        alarm = result["alarm"]
        self.assertEqual("intrusion", alarm["kind"])
        self.assertTrue(alarm["details"]["restricted"])
        commands = {item.get("command") for item in alarm["linkage"] if item["channel"] == "access_control"}
        self.assertEqual({"lockdown", "suspend_entry"}, commands)

    def test_unknown_badge_still_raises_alarm(self) -> None:
        result = self.app.safety.report_position("positioning", person_id="P-999", zone="settler-deck")
        self.assertTrue(result["intrusion"])
        self.assertFalse(result["alarm"]["details"]["person_known"])

    def test_intrusion_deduplicates_while_active(self) -> None:
        first = self.app.safety.report_position("positioning", person_id="P-001", zone="oxygen-stand")
        second = self.app.safety.report_position("positioning", person_id="P-001", zone="oxygen-stand")
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(1, self.app.safety.status()["counts"]["alarms_unresolved"])

    def test_wrong_zone_counts_as_intrusion(self) -> None:
        _enter(self.app, zone="reactor-floor")
        result = self.app.safety.report_position("positioning", person_id="P-001", zone="settler-deck")
        self.assertTrue(result["intrusion"])
        self.assertEqual("reactor-floor", result["alarm"]["details"]["registered_zone"])


class SosAlarmTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def test_sos_raises_critical_alarm_with_evacuation_linkage(self) -> None:
        _enter(self.app)
        result = self.app.safety.sos("help-button", person_id="P-001", note="头晕")
        alarm = result["alarm"]
        self.assertEqual("sos", alarm["kind"])
        self.assertEqual("critical", alarm["severity"])
        self.assertEqual("reactor-floor", alarm["zone"])  # 未指定区域时取在场区域
        commands = {item.get("command") for item in alarm["linkage"] if item["channel"] == "access_control"}
        self.assertEqual({"release_evacuation", "suspend_entry"}, commands)
        broadcast = next(item for item in alarm["linkage"] if item["channel"] == "broadcast")
        self.assertIn("张三", broadcast["receipt"]["message"])

    def test_sos_accepts_unregistered_person(self) -> None:
        result = self.app.safety.sos("help-button", person_id="P-999", zone="oxygen-stand")
        self.assertEqual("sos", result["alarm"]["kind"])
        self.assertFalse(result["alarm"]["details"]["person_known"])

    def test_sos_without_location_broadcasts_plant_wide(self) -> None:
        result = self.app.safety.sos("help-button", person_id="P-999")
        alarm = result["alarm"]
        self.assertEqual("plant", alarm["zone"])
        broadcast = next(item for item in alarm["linkage"] if item["channel"] == "broadcast")
        self.assertEqual("plant", broadcast["receipt"]["zone"])
        self.assertEqual([], [item for item in alarm["linkage"] if item["channel"] == "access_control"])


class AlarmHandlingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        _register(self.app)

    def _raise_sos(self):
        return self.app.safety.sos("help-button", person_id="P-001", zone="reactor-floor")["alarm"]

    def test_acknowledge_resolve_flow(self) -> None:
        alarm = self._raise_sos()
        with self.assertRaises(ValidationError):
            self.app.safety.resolve("dispatcher", alarm_id=alarm["alarm_id"], note="")
        acked = self.app.safety.acknowledge("dispatcher", alarm_id=alarm["alarm_id"])
        self.assertEqual("acknowledged", acked["alarm"]["status"])
        self.assertEqual("dispatcher", acked["alarm"]["acknowledged_by"])
        with self.assertRaises(GuardViolation):
            self.app.safety.acknowledge("dispatcher", alarm_id=alarm["alarm_id"])
        resolved = self.app.safety.resolve("dispatcher", alarm_id=alarm["alarm_id"], note="人员已救出，送医")
        self.assertEqual("resolved", resolved["alarm"]["status"])
        self.assertEqual("人员已救出，送医", resolved["alarm"]["resolve_note"])
        events = self.app.safety.alarm_events()
        self.assertEqual(
            ["raised", "acknowledged", "resolved"], [event["event"] for event in events]
        )

    def test_unknown_alarm_rejected(self) -> None:
        with self.assertRaises(NotFoundError):
            self.app.safety.acknowledge("dispatcher", alarm_id="AL-none")
        with self.assertRaises(NotFoundError):
            self.app.safety.resolve("dispatcher", alarm_id="AL-none", note="x")


class PersistenceTest(unittest.TestCase):
    def test_restart_preserves_presence_passes_and_alarms(self) -> None:
        root = make_root()
        app = make_app(root=root)
        _register(app)
        _enter(app, max_dwell_seconds=60.0)
        app.clock.advance(61.0)
        app.safety.sweep("control-system")
        clock = app.clock

        restarted = Application(app.settings, clock=clock)
        status = restarted.safety.status()
        self.assertEqual(1, status["present_total"])
        self.assertEqual(1, status["counts"]["alarms_unresolved"])
        self.assertEqual(1, status["counts"]["passes_active"])
        person = status["zones"]["reactor-floor"]["persons"][0]
        self.assertEqual("shift-lead", person["approver"])
        # 重启后超时报警不重复触发
        again = restarted.safety.sweep("control-system")
        self.assertEqual([], again["raised"])


class ZoneCatalogTest(unittest.TestCase):
    def test_console_zone_catalog_includes_safety(self) -> None:
        app = make_app()
        zones = dict(app.namespace.iter_zones())
        self.assertEqual("safety", zones["safety"])

    def test_zone_levels_are_declared(self) -> None:
        levels = {zone: info["level"] for zone, info in ZONES.items()}
        self.assertEqual("restricted", levels["tapping-aisle"])
        self.assertEqual("general", levels["reactor-floor"])


class QueryReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()

    def test_presence_and_personnel_reports(self) -> None:
        _register(self.app)
        _register(self.app, person_id="P-002", name="李四")
        _enter(self.app)
        presence = self.app.safety.presence_report()
        self.assertEqual(1, presence["present_total"])
        self.assertEqual(["P-001"], [p["person_id"] for p in presence["zones"]["reactor-floor"]])
        roster = self.app.safety.personnel_report()
        self.assertEqual({"P-001", "P-002"}, {p["person_id"] for p in roster})
        self.assertTrue(self.app.safety.is_zone_suspended("reactor-floor") is False)

    def test_zone_suspension_query_follows_alarm_lifecycle(self) -> None:
        _register(self.app)
        alarm = self.app.safety.sos("help-button", person_id="P-001", zone="reactor-floor")["alarm"]
        self.assertTrue(self.app.safety.is_zone_suspended("reactor-floor"))
        self.assertFalse(self.app.safety.is_zone_suspended("settler-deck"))
        self.app.safety.resolve("dispatcher", alarm_id=alarm["alarm_id"], note="误触，已确认")
        self.assertFalse(self.app.safety.is_zone_suspended("reactor-floor"))


if __name__ == "__main__":
    unittest.main()
