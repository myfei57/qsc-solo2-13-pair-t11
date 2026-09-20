"""高温区人员安全：许可审批、进出登记、超时/闯入/求助报警、联动与留痕。"""

from __future__ import annotations

import unittest

from flashsmelter.application import Application
from flashsmelter.config import Settings
from flashsmelter.errors import GuardViolation, NotFoundError, ValidationError

from .helpers import make_app, make_root


class PermitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()

    def test_issue_permit_records_approver(self) -> None:
        permit = self.app.safety.issue_permit("control-room", person_id="zhangsan", approved_by="lisi")
        self.assertEqual("zhangsan", permit["person_id"])
        self.assertEqual("lisi", permit["approved_by"])
        self.assertEqual("work", permit["kind"])
        self.assertFalse(permit["revoked"])
        self.assertEqual(
            self.app.settings.safety_default_max_dwell_seconds, permit["max_dwell_seconds"]
        )
        # 审批留痕：审计流里能查到谁批的
        events = self.app.audit_events(action="issue_permit")
        self.assertEqual(1, len(events))
        self.assertEqual("lisi", events[0]["details"]["approved_by"])

    def test_permit_requires_approver_and_valid_kind(self) -> None:
        with self.assertRaises(ValidationError):
            self.app.safety.issue_permit("control-room", person_id="zhangsan", approved_by="")
        with self.assertRaises(ValidationError):
            self.app.safety.issue_permit(
                "control-room", person_id="zhangsan", approved_by="lisi", kind="vip"
            )

    def test_dwell_cap_enforced(self) -> None:
        cap = self.app.settings.safety_max_dwell_cap_seconds
        with self.assertRaises(GuardViolation):
            self.app.safety.issue_permit(
                "control-room", person_id="zhangsan", approved_by="lisi", max_dwell_seconds=cap + 1
            )
        # 走动作注册表（HTTP/CLI 同路径）时由参数层拦截
        with self.assertRaises(ValidationError):
            self.app.invoke(
                "safety.issue_permit",
                {"person_id": "zhangsan", "approved_by": "lisi", "max_dwell_seconds": cap + 1},
            )


class EntryExitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        self.permit = self.app.safety.issue_permit(
            "control-room", person_id="zhangsan", approved_by="lisi", max_dwell_seconds=60.0
        )

    def test_enter_exit_flow(self) -> None:
        status = self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])
        self.assertEqual(1, status["occupant_count"])
        occupant = status["occupants"][0]
        self.assertEqual("lisi", occupant["approved_by"])
        self.assertEqual(60.0, occupant["remaining_seconds"])
        self.app.clock.advance(30.0)
        status = self.app.safety.exit("gate", person_id="zhangsan")
        self.assertEqual(0, status["occupant_count"])
        self.assertEqual(1, status["counters"]["exits"])
        kinds = [event["kind"] for event in self.app.safety.events()]
        self.assertEqual(["permit-issued", "entry", "exit"], kinds)
        exit_event = self.app.safety.events()[-1]
        self.assertEqual(30.0, exit_event["dwell_seconds"])
        self.assertFalse(exit_event["overdue"])

    def test_enter_rejects_bad_permit(self) -> None:
        with self.assertRaises(NotFoundError):
            self.app.safety.enter("gate", person_id="zhangsan", permit_id="P-missing")
        with self.assertRaises(GuardViolation):  # 人与许可不符
            self.app.safety.enter("gate", person_id="wangwu", permit_id=self.permit["permit_id"])

    def test_enter_rejects_expired_permit(self) -> None:
        self.app.clock.advance(self.app.settings.safety_permit_valid_seconds + 1)
        with self.assertRaises(GuardViolation):
            self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])

    def test_duplicate_enter_rejected(self) -> None:
        self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])
        with self.assertRaises(GuardViolation):
            self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])

    def test_exit_unknown_person(self) -> None:
        with self.assertRaises(NotFoundError):
            self.app.safety.exit("gate", person_id="nobody")

    def test_revoke_permit_blocked_while_inside(self) -> None:
        self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])
        with self.assertRaises(GuardViolation):  # 人还在区内，禁止注销
            self.app.safety.revoke_permit(
                "control-room", permit_id=self.permit["permit_id"], reason="换班"
            )
        self.app.safety.exit("gate", person_id="zhangsan")
        revoked = self.app.safety.revoke_permit(
            "control-room", permit_id=self.permit["permit_id"], reason="换班"
        )
        self.assertTrue(revoked["revoked"])
        self.assertEqual("换班", revoked["revoke_reason"])
        with self.assertRaises(GuardViolation):  # 已注销许可不能进
            self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])


class AlarmTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        self.permit = self.app.safety.issue_permit(
            "control-room", person_id="zhangsan", approved_by="lisi", max_dwell_seconds=60.0
        )
        self.app.safety.enter("gate", person_id="zhangsan", permit_id=self.permit["permit_id"])

    def test_overstay_sweep_raises_alarm_and_broadcasts(self) -> None:
        self.app.clock.advance(61.0)
        result = self.app.safety.sweep("safety-monitor")
        self.assertEqual(["zhangsan"], result["overdue"])
        self.assertEqual(1, len(result["raised_alarms"]))
        self.assertEqual("alarming", result["state"])
        self.assertEqual("alarming", self.app.safety.state)
        status = self.app.safety.status()
        self.assertEqual(1, status["active_alarm_count"])
        alarm = status["active_alarms"][0]
        self.assertEqual("overstay", alarm["kind"])
        self.assertEqual("zhangsan", alarm["person_id"])
        # 联动：广播已写入持久流水，回执随报警留痕
        self.assertIn("broadcast", alarm["linkage"])
        broadcasts = self.app.store.read_stream("safety/broadcast")
        self.assertEqual(1, len(broadcasts))
        self.assertEqual("warning", broadcasts[0].payload["level"])
        self.assertIn("zhangsan", broadcasts[0].payload["message"])
        # 重复扫描不重复报警，只累加报告次数
        again = self.app.safety.sweep("safety-monitor")
        self.assertEqual([], again["raised_alarms"])
        self.assertEqual(2, self.app.safety.status()["active_alarms"][0]["reports"])

    def test_entry_blocked_while_alarming_unless_rescue(self) -> None:
        self.app.clock.advance(61.0)
        self.app.safety.sweep("safety-monitor")
        work = self.app.safety.issue_permit("control-room", person_id="wangwu", approved_by="lisi")
        with self.assertRaises(GuardViolation):
            self.app.safety.enter("gate", person_id="wangwu", permit_id=work["permit_id"])
        rescue = self.app.safety.issue_permit(
            "control-room", person_id="rescuer", approved_by="lisi", kind="rescue"
        )
        status = self.app.safety.enter("gate", person_id="rescuer", permit_id=rescue["permit_id"])
        self.assertEqual(2, status["occupant_count"])

    def test_sos_from_unregistered_person_triggers_evacuate(self) -> None:
        alarm = self.app.safety.sos("sos-button", person_id="stranger", location="沉淀池二层")
        self.assertEqual("sos", alarm["kind"])
        self.assertFalse(alarm["details"]["registered"])
        self.assertEqual("沉淀池二层", alarm["details"]["location"])
        self.assertEqual("emergency", alarm["linkage"]["broadcast"]["level"])
        self.assertEqual("evacuate", alarm["linkage"]["access"]["mode"])
        self.assertEqual("evacuate", self.app.safety.status()["access_modes"]["hot-zone"])

    def test_intrusion_forbidden_zone_locks_down(self) -> None:
        with self.assertRaises(ValidationError):
            self.app.safety.intrusion("positioning", person_id="zhangsan", zone="office")
        alarm = self.app.safety.intrusion("positioning", person_id="zhangsan", zone="tap-face")
        self.assertEqual("intrusion", alarm["kind"])
        self.assertEqual("tap-face", alarm["zone"])
        self.assertEqual("lockdown", alarm["linkage"]["access"]["mode"])
        self.assertEqual("lockdown", self.app.safety.status()["access_modes"]["tap-face"])

    def test_acknowledge_and_resolve_restores_normal(self) -> None:
        alarm = self.app.safety.sos("sos-button", person_id="zhangsan")
        alarm_id = alarm["alarm_id"]
        with self.assertRaises(GuardViolation):  # 解除必须填写处理说明
            self.app.safety.resolve("control-room", alarm_id=alarm_id, note="")
        acked = self.app.safety.acknowledge("control-room", alarm_id=alarm_id)
        self.assertEqual("acknowledged", acked["status"])
        self.assertEqual("control-room", acked["ack_by"])
        resolved = self.app.safety.resolve("control-room", alarm_id=alarm_id, note="人已救出，送医观察")
        self.assertEqual("resolved", resolved["status"])
        self.assertEqual("watching", resolved["watch_state"])
        # 全部解除后门禁恢复常态、广播播报解除
        self.assertEqual("normal", self.app.safety.status()["access_modes"]["hot-zone"])
        broadcasts = self.app.store.read_stream("safety/broadcast")
        self.assertEqual("info", broadcasts[-1].payload["level"])
        # 处理留痕
        events = [event for event in self.app.safety.events() if event["kind"] == "alarm-resolved"]
        self.assertEqual(1, len(events))
        self.assertEqual("人已救出，送医观察", events[0]["note"])
        self.assertEqual("control-room", events[0]["resolve_by"])
        with self.assertRaises(GuardViolation):  # 不能重复解除
            self.app.safety.resolve("control-room", alarm_id=alarm_id, note="重复处理")

    def test_resolve_unknown_alarm(self) -> None:
        with self.assertRaises(NotFoundError):
            self.app.safety.resolve("control-room", alarm_id="A-missing", note="x")


class PersistenceTest(unittest.TestCase):
    def test_state_survives_restart(self) -> None:
        root = make_root()
        app = make_app(root=root)
        permit = app.safety.issue_permit(
            "control-room", person_id="zhangsan", approved_by="lisi", max_dwell_seconds=60.0
        )
        app.safety.enter("gate", person_id="zhangsan", permit_id=permit["permit_id"])
        app.clock.advance(61.0)
        app.safety.sweep("safety-monitor")
        # 同一状态目录重建应用：在区人员、未解除报警与许可都要装回来
        rebuilt = Application(Settings(root=root), clock=app.clock)
        status = rebuilt.safety.status()
        self.assertEqual("alarming", status["state"])
        self.assertEqual(1, status["occupant_count"])
        self.assertEqual(1, status["active_alarm_count"])
        self.assertEqual("overstay", status["active_alarms"][0]["kind"])
        permits = rebuilt.safety.permits()
        self.assertEqual(1, len(permits))
        self.assertEqual("lisi", permits[0]["approved_by"])


class ConsoleWiringTest(unittest.TestCase):
    def test_safety_actions_registered_and_invokable(self) -> None:
        app = make_app()
        for expected in (
            "safety.issue_permit",
            "safety.revoke_permit",
            "safety.enter",
            "safety.exit",
            "safety.sos",
            "safety.intrusion",
            "safety.sweep",
            "safety.acknowledge",
            "safety.resolve",
        ):
            self.assertIn(expected, set(app.actions))
        self.assertEqual("safety", app.safety.snapshot()["zone"])
        # 通过动作注册表走完整流程（与 HTTP/CLI 同一路径）
        permit = app.invoke("safety.issue_permit", {"person_id": "zhangsan", "approved_by": "lisi"})
        app.invoke("safety.enter", {"person_id": "zhangsan", "permit_id": permit["permit_id"]})
        result = app.invoke("safety.sweep", {})
        self.assertEqual(1, result["checked"])
        self.assertEqual([], result["overdue"])
        alarm = app.invoke("safety.sos", {"person_id": "zhangsan"})
        resolved = app.invoke(
            "safety.resolve", {"alarm_id": alarm["alarm_id"], "note": "确认无碍"}
        )
        self.assertEqual("watching", resolved["watch_state"])


if __name__ == "__main__":
    unittest.main()
