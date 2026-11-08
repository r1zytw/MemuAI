"""5.0 multi-account Telegram: two bound accounts share one bot.

Everything runs offline: MemuAI data lives in a temporary directory, the
pairing state machine and the notification targeting are exercised directly.
"""
import asyncio
import os
import tempfile
import unittest

if not os.environ.get("MEMUAI_DATA_DIR"):
    os.environ["MEMUAI_DATA_DIR"] = tempfile.mkdtemp(prefix="memuai-multiacc-")

from app import pgdata, telegram_bot, telegram_pairing  # noqa: E402

FIRST = {"id": "111", "first_name": "Alice", "username": "alice"}
SECOND = {"id": "222", "first_name": "Bob", "username": "bob"}
THIRD = {"id": "333", "first_name": "Carol", "username": "carol"}


class MultiAccountTest(unittest.TestCase):
    def setUp(self) -> None:
        pgdata.save_preferences({"telegram_chat_id": "", "telegram_enabled": False})
        pgdata.update_telegram_state(lambda data: {})

    def test_two_accounts_bind_third_is_refused(self) -> None:
        first = telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        self.assertTrue(first["added"])
        second = telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        self.assertTrue(second["added"])
        third = telegram_pairing.complete_pairing({"id": THIRD["id"]}, THIRD)
        self.assertTrue(third["full"])
        chats = [row["chat_id"] for row in telegram_pairing.owners()]
        self.assertEqual(chats, [FIRST["id"], SECOND["id"]])
        # the first bound account stays the legacy pref so old consumers stay correct
        self.assertEqual(pgdata.load_preferences()["telegram_chat_id"], FIRST["id"])

    def test_rebinding_refreshes_without_duplicates(self) -> None:
        telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        again = telegram_pairing.complete_pairing({"id": SECOND["id"]},
                                                  {"id": SECOND["id"], "first_name": "Bobby"})
        self.assertFalse(again["added"])
        rows = telegram_pairing.owners()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["name"], "Bobby")

    def test_notification_targets_follow_the_choice(self) -> None:
        telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        prefs = pgdata.load_preferences()
        self.assertEqual(telegram_bot.notification_chats(prefs, "all"), [FIRST["id"], SECOND["id"]])
        self.assertEqual(telegram_bot.notification_chats(prefs, "1"), [FIRST["id"]])
        self.assertEqual(telegram_bot.notification_chats(prefs, "2"), [SECOND["id"]])

    def test_missing_slot_falls_back_to_every_bound_chat(self) -> None:
        telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        telegram_pairing.unpair(SECOND["id"])
        prefs = pgdata.load_preferences()
        # a task pointed at account 2 must not silently drop its reminder
        self.assertEqual(telegram_bot.notification_chats(prefs, "2"), [FIRST["id"]])

    def test_unpair_one_keeps_the_other_working(self) -> None:
        telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        telegram_pairing.unpair(FIRST["id"])
        prefs = pgdata.load_preferences()
        self.assertEqual(prefs["telegram_chat_id"], SECOND["id"])
        self.assertTrue(telegram_bot._allowed(prefs, SECOND["id"], SECOND["id"]))
        self.assertFalse(telegram_bot._allowed(prefs, FIRST["id"], FIRST["id"]))
        self.assertIn(SECOND["id"], telegram_bot.authorized_user_ids(prefs))
        self.assertNotIn(FIRST["id"], telegram_bot.authorized_user_ids(prefs))

    def test_legacy_single_owner_state_still_works(self) -> None:
        pgdata.update_telegram_state(lambda data: {**data, "owner": {"chat_id": "999", "user_id": "999",
                                                                     "name": "Legacy", "paired_at": 1.0}})
        self.assertEqual([row["chat_id"] for row in telegram_pairing.owners()], ["999"])
        prefs = pgdata.load_preferences()
        prefs["telegram_chat_id"] = "999"
        self.assertEqual(telegram_bot.notification_chats(prefs, "all"), ["999"])

    def test_status_reports_both_accounts(self) -> None:
        telegram_pairing.complete_pairing({"id": FIRST["id"]}, FIRST)
        telegram_pairing.complete_pairing({"id": SECOND["id"]}, SECOND)
        status = telegram_pairing.status(pgdata.load_preferences())
        self.assertEqual([row["chat_id"] for row in status["owners"]], [FIRST["id"], SECOND["id"]])
        self.assertTrue(status["paired"])


if __name__ == "__main__":
    unittest.main()
