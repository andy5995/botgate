"""ANSI countdown regression checks, including real socket updates."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import botgate_proxy as botgate


class CountdownColorTests(unittest.TestCase):
    def build(self, template, timeout=20):
        with mock.patch.object(botgate, "get_prompt_template", return_value=template):
            return botgate.build_prompt({"timeout_seconds": timeout})

    def test_initial_art_and_coordinates_are_preserved(self):
        template = b"\x1b[32mWait \x1b[1;31m##\x1b[0m seconds\r\n"
        initial, countdown, rows = self.build(template)
        self.assertEqual(initial, template.replace(b"##", b"20"))
        self.assertEqual(countdown[:3], (1, 6, 2))
        self.assertEqual(rows, 2)
        self.assertEqual(countdown[3], b"\x1b[0m\x1b[32m\x1b[1;31m")
        self.assertEqual(countdown[4], b"\x1b[0m\x1b[0m")

    def test_color_and_attributes_carry_across_lines(self):
        template = b"\x1b[1;31;44mTITLE\r\nTime: ##\x1b[0m\r\n"
        initial, countdown, _ = self.build(template)
        self.assertEqual(countdown[:3], (2, 7, 2))
        self.assertEqual(countdown[3], b"\x1b[0m\x1b[1;31;44m")
        self.assertIn(b"Time: 20", initial)

    def test_partial_attribute_changes_and_final_color(self):
        template = b"\x1b[1m\x1b[31m\x1b[44m\x1b[22m##\x1b[32m done"
        _, countdown, _ = self.build(template)
        self.assertEqual(countdown[3], b"\x1b[0m\x1b[1m\x1b[31m\x1b[44m\x1b[22m")
        self.assertEqual(countdown[4], countdown[3] + b"\x1b[32m")

    def test_full_and_empty_resets_discard_old_formatting(self):
        for reset in (b"\x1b[0m", b"\x1b[m", b"\x1b[00;34m"):
            with self.subTest(reset=reset):
                _, countdown, _ = self.build(b"\x1b[31mOLD" + reset + b"##\x1b[32m")
                self.assertEqual(countdown[3], b"\x1b[0m" + reset)

    def test_extended_colors_do_not_treat_zero_components_as_resets(self):
        for color in (b"\x1b[38;5;0m", b"\x1b[38;2;255;0;0m",
                      b"\x1b[48;2;0;0;255m", b"\x1b[038;02;255;0;0m",
                      b"\x1b[38:2::255:0:0m"):
            with self.subTest(color=color):
                _, countdown, _ = self.build(b"\x1b[1m" + color + b"##\x1b[0m")
                self.assertEqual(countdown[:3], (1, 1, 2))
                self.assertEqual(countdown[3], b"\x1b[0m\x1b[1m" + color)

    def test_only_formatting_is_replayed(self):
        _, countdown, _ = self.build(b"\x1b[31m\x1b[2J\x1b[HART ##\x1b[0m")
        self.assertEqual(countdown[3], b"\x1b[0m\x1b[31m")
        self.assertNotIn(b"ART", countdown[3])
        self.assertNotIn(b"\x1b[2J", countdown[3])

    def test_uncolored_prompts_add_no_sgr(self):
        initial, countdown, _ = self.build(b"Time: ### seconds", timeout=9)
        self.assertEqual(initial, b"Time:   9 seconds")
        self.assertEqual(countdown, (1, 7, 3, b"", b""))

    def test_same_field_and_end_format_needs_no_reapplication(self):
        _, countdown, _ = self.build(b"\x1b[31mTime ## seconds")
        self.assertEqual(countdown[3:], (b"", b""))

    def test_no_placeholder_remains_static(self):
        template = b"\x1b[31mNo countdown\x1b[0m"
        self.assertEqual(self.build(template), (template, None, 1))

    def receive_until(self, client, marker):
        received = bytearray()
        while marker not in received:
            chunk = client.recv(65536)
            self.assertTrue(chunk, "gate closed before expected output")
            received.extend(chunk)
        return bytes(received)

    def run_socket_gate(self, template, live, check):
        caller, server = socket.socketpair()
        caller.settimeout(4)
        result = []
        cfg = {"timeout_seconds": 5, "required_hits": 2, "live_countdown": live}
        worker = threading.Thread(target=lambda: result.append(botgate.run_gate(server, cfg, ("127.0.0.1", 0))), daemon=True)
        with mock.patch.object(botgate, "get_prompt_template", return_value=template):
            try:
                worker.start()
                check(caller)
                caller.sendall(b"\x1b*")
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(result, [(True, len(template.split(b"\r\n")))])
            finally:
                caller.close()
                server.close()
                worker.join(2)

    def test_real_ticks_keep_red_and_restore_green(self):
        template = b"\x1b[0;32mWait \x1b[1;31;44m##\x1b[0;32m seconds\r\n"
        def check(caller):
            initial = self.receive_until(caller, b"seconds\r\n")
            self.assertEqual(initial, b"\x1b[2J\x1b[H" + template.replace(b"##", b" 5"))
            for number in (4, 3):
                # Field is bright red on blue; following output returns green.
                expected = (b"\x1b[1;6H\x1b[0m\x1b[0;32m\x1b[1;31;44m"
                            + ("%2d" % number).encode("ascii") + b"\x1b[0m\x1b[0;32m")
                self.assertEqual(self.receive_until(caller, expected), expected)
        self.run_socket_gate(template, True, check)

    def test_disabled_countdown_does_not_send_updates(self):
        template = b"\x1b[31mWait ##\x1b[0m seconds\r\n"
        def check(caller):
            initial = self.receive_until(caller, b"seconds\r\n")
            self.assertEqual(initial, b"\x1b[2J\x1b[H" + template.replace(b"##", b" 5"))
            time.sleep(1.1)
            caller.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                caller.recv(65536)
        self.run_socket_gate(template, False, check)


if __name__ == "__main__":
    unittest.main()
