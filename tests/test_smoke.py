"""Local socket/process smoke checks; no production server or live feed needed."""
import configparser
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import botgate_proxy as botgate


class SocketSmokeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        (root / "geo").mkdir()
        for name in ["ip.can", "ip-silent.can", "host.can", "ipfilter_exempt.cfg"]:
            (root / name).write_text("")
        self.backend_listener = socket.socket()
        self.backend_listener.bind(("127.0.0.1", 0))
        self.backend_listener.listen(2)
        self.backend_listener.settimeout(1)
        self.addCleanup(self.backend_listener.close)
        self.cfg = {
            "can_dir": str(root), "geo_dir": str(root / "geo"), "abuseipdb_update_hours": 0,
            "dns_lookup_enabled": False, "listen_port": 23230, "backend_host": "127.0.0.1",
            "backend_port": self.backend_listener.getsockname()[1], "ip_cap": 2,
            "timeout_seconds": 1, "required_hits": 2, "live_countdown": True,
            "prompt_file": "", "send_proxy_protocol": False,
        }
        self.blocks = botgate.BlockLists(self.cfg)
        self.addCleanup(self.blocks.abuseipdb.stop)
        self.limiter = mock.Mock()
        self.limiter.is_banned.return_value = False
        self.limiter.record_and_check.return_value = False
        self.caller, self.client = socket.socketpair()
        self.caller.settimeout(2)
        self.addCleanup(self.caller.close)
        self.addCleanup(self.client.close)
        self.worker = None
        self.accepted = []
        self.addCleanup(self.finish)

    def finish(self):
        self.caller.close()
        self.client.close()
        for accepted in self.accepted:
            accepted.close()
        if self.worker is not None:
            self.worker.join(2)
            self.assertFalse(self.worker.is_alive(), "connection handler did not exit")

    def start_handler(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        self.worker = threading.Thread(target=botgate.handle_client,
                                       args=(self.client, ("203.0.113.42", 4567), self.cfg,
                                             self.blocks, self.limiter, slots), daemon=True)
        self.worker.start()
        return slots

    def receive_until(self, sock, marker):
        data = bytearray()
        deadline = time.monotonic() + 2
        while marker not in data:
            if time.monotonic() >= deadline:
                self.fail("timed out receiving {!r}".format(marker))
            chunk = sock.recv(4096)
            if not chunk:
                self.fail("socket closed before {!r}; received {!r}".format(marker, bytes(data)))
            data.extend(chunk)
        return bytes(data)

    def pass_and_relay(self, challenge):
        slots = self.start_handler()
        prompt = self.receive_until(self.caller, b"\x1b[2J\x1b[H")
        self.assertIn(b"\x1b[2J\x1b[H", prompt)
        self.backend_listener.settimeout(0.05)
        with self.assertRaises(socket.timeout):
            self.backend_listener.accept()
        self.backend_listener.settimeout(2)
        self.caller.sendall(challenge)
        backend, _ = self.backend_listener.accept()
        backend.settimeout(2)
        self.accepted.append(backend)
        if self.cfg["send_proxy_protocol"]:
            header = self.receive_until(backend, b"\r\n")
            self.assertTrue(header.startswith(b"PROXY TCP4 203.0.113.42 127.0.0.1 4567 "))
        backend.sendall(b"BBS_READY")
        self.receive_until(self.caller, b"BBS_READY")
        self.caller.sendall(b"UPLOAD_CHECK")
        self.receive_until(backend, b"UPLOAD_CHECK")
        backend.sendall(b"DOWNLOAD_CHECK")
        self.receive_until(self.caller, b"DOWNLOAD_CHECK")
        self.caller.close()
        self.worker.join(2)
        self.assertFalse(self.worker.is_alive())
        self.assertTrue(slots.acquire(blocking=False), "global slot leaked")

    def test_esc_gate_and_bidirectional_relay(self):
        self.pass_and_relay(b"\x1b\x1b")

    def test_star_gate_ascii_prompt_and_static_countdown(self):
        prompt = Path(self.directory.name) / "prompt.asc"
        prompt.write_bytes(b"ASCII custom prompt: ## seconds\n")
        self.cfg.update(prompt_file=str(prompt), live_countdown=False)
        self.pass_and_relay(b"**")

    def test_mixed_gate_ansi_prompt_and_proxy_header(self):
        prompt = Path(self.directory.name) / "prompt.ans"
        prompt.write_bytes(b"\x1b[31mANSI prompt\x1b[0m: ## seconds\r\n")
        self.cfg.update(prompt_file=str(prompt), send_proxy_protocol=True)
        self.pass_and_relay(b"\x1b*")

    def test_scripted_payload_rejected_without_backend_connection(self):
        self.start_handler()
        self.caller.sendall(b"GET / HTTP/1.1\r\n")
        self.worker.join(2)
        self.assertFalse(self.worker.is_alive())
        self.backend_listener.settimeout(0.05)
        with self.assertRaises(socket.timeout):
            self.backend_listener.accept()

    def test_timeout_without_backend_connection(self):
        self.cfg["timeout_seconds"] = 0.15
        self.start_handler()
        self.worker.join(2)
        self.assertFalse(self.worker.is_alive())
        self.backend_listener.settimeout(0.05)
        with self.assertRaises(socket.timeout):
            self.backend_listener.accept()

    def test_backend_unavailable_releases_connection_slot(self):
        self.backend_listener.close()
        with self.assertLogs(botgate.log, level="WARNING") as captured:
            slots = self.start_handler()
            self.caller.sendall(b"**")
            self.worker.join(7)
        self.assertFalse(self.worker.is_alive())
        self.assertTrue(slots.acquire(blocking=False))
        self.assertIn("Could not reach backend", "\n".join(captured.output))

    def test_per_ip_connection_cap_rejects_before_gate(self):
        self.cfg["ip_cap"] = 1
        self.assertTrue(botgate.try_acquire_ip_slot("203.0.113.42", 1))
        self.addCleanup(botgate.release_ip_slot, "203.0.113.42")
        with mock.patch.object(botgate, "run_gate") as gate, \
                mock.patch.object(botgate.socket, "create_connection") as backend:
            self.start_handler()
            self.worker.join(2)
            self.assertFalse(self.worker.is_alive())
            gate.assert_not_called()
            backend.assert_not_called()

    def test_telnet_negotiation_does_not_count_as_challenge_hits(self):
        parser = botgate.TelnetFilter()
        self.assertEqual(parser.feed(bytes([botgate.IAC, botgate.WILL])), b"")
        self.assertEqual(parser.feed(bytes([botgate.OPT_ECHO]) + b"**"), b"**")

    def test_global_cap_rejects_before_creating_a_worker(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.5)
        self.addCleanup(listener.close)
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        cfg = dict(self.cfg, max_connections=1)
        acceptor = threading.Thread(target=botgate.accept_loop,
                                    args=(listener, cfg, self.blocks, self.limiter, slots), daemon=True)
        with mock.patch.object(botgate.threading, "Thread") as new_worker, \
                self.assertLogs(botgate.log, level="WARNING") as captured:
            acceptor.start()
            with socket.create_connection(listener.getsockname(), timeout=2) as caller:
                self.assertEqual(caller.recv(4096), b"")
            acceptor.join(2)
            self.assertFalse(acceptor.is_alive())
            new_worker.assert_not_called()
        self.assertIn("global connection limit", captured.output[0])


class ProcessSmokeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "can").mkdir()
        (self.root / "geo").mkdir()
        (self.root / "elsewhere").mkdir()
        for name in ["ip.can", "ip-silent.can", "host.can", "ipfilter_exempt.cfg"]:
            (self.root / "can" / name).write_text("")
        shutil.copyfile(botgate.__file__, str(self.root / "botgate_proxy.py"))
        self.backend = socket.socket()
        self.backend.bind(("127.0.0.1", 0))
        self.backend.listen(2)
        self.backend.settimeout(0.05)
        self.addCleanup(self.backend.close)
        reserved = [socket.socket(), socket.socket()]
        for sock in reserved:
            sock.bind(("127.0.0.1", 0))
        self.ports = [sock.getsockname()[1] for sock in reserved]
        for sock in reserved:
            sock.close()
        self.logfile = self.root / "process.log"
        self.process = None
        self.addCleanup(self.stop_process)

    def stop_process(self):
        if self.process is not None:
            self.process.terminate()
            self.process.communicate(timeout=5)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                self.fail("BotGate exited early: {} {}".format(stdout, stderr))
            time.sleep(0.02)
        self.fail("process condition timed out; log: " + self.read_log())

    def read_log(self):
        return self.logfile.read_text() if self.logfile.exists() else ""

    def run_process(self, successful_update):
        cfg = configparser.ConfigParser()
        cfg.read_string(botgate.DEFAULT_CONFIG)
        cfg["proxy"].update({"listen_port": str(self.ports[0]), "backend_host": "127.0.0.1",
                             "backend_port": str(self.backend.getsockname()[1]), "log_file": "process.log",
                             "abuseipdb update": "12", "ip_cap": "0", "rate_limit_hits": "0"})
        cfg["Listener2"] = {"listen_port": str(self.ports[1]), "backend_host": "127.0.0.1",
                            "backend_port": str(self.backend.getsockname()[1])}
        with (self.root / "botgate_proxy.cfg").open("w") as config:
            cfg.write(config)
        # Keep the process deterministic and offline; a separate manual check
        # exercises the production HTTPS downloader against the actual source.
        setup = ("b.AbuseIPDBFeed._download=lambda self: b'# Number of ips: 1\\n127.0.0.1\\n';"
                 if successful_update else
                 "b.AbuseIPDBFeed._download=lambda self: (_ for _ in ()).throw(TimeoutError('offline fixture'));")
        runner = "import sys;sys.path.insert(0,sys.argv[1]);import botgate_proxy as b;" + setup + "b.main()"
        self.process = subprocess.Popen([sys.executable, "-c", runner, str(self.root)],
                                        cwd=str(self.root / "elsewhere"), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, universal_newlines=True)
        target = "abuseipdb.can updated:" if successful_update else "abuseipdb.can update failed:"
        self.wait_for(lambda: target in self.read_log())
        self.assertIn("BotGate running with 2 listener(s)", self.read_log())

    def check_both_ports_block_before_backend(self):
        for port in self.ports:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as caller:
                self.assertEqual(caller.recv(4096), b"")
        self.wait_for(lambda: self.read_log().count("blocked by abuseipdb.can.") == 2)
        for port in self.ports:
            self.assertIn("[WARNING] [{}] 127.0.0.1 blocked by abuseipdb.can.".format(port), self.read_log())
        with self.assertRaises(socket.timeout):
            self.backend.accept()
        self.assertEqual(self.read_log().count("checking for an update now"), 1)
        self.assertIsNone(self.process.poll())

    def test_new_snapshot_activates_on_both_listeners_without_restart(self):
        self.run_process(successful_update=True)
        self.check_both_ports_block_before_backend()
        self.assertIn("AUTO-MANAGED", (self.root / "can" / "abuseipdb.can").read_text())

    def test_offline_start_uses_existing_cache_on_both_listeners(self):
        cache = self.root / "can" / "abuseipdb.can"
        original = b"; old cached snapshot\n127.0.0.1\n"
        cache.write_bytes(original)
        self.run_process(successful_update=False)
        self.check_both_ports_block_before_backend()
        self.assertEqual(cache.read_bytes(), original)
        self.assertIn("[INFO] abuseipdb.can update failed: offline fixture; keeping previous list.", self.read_log())


if __name__ == "__main__":
    unittest.main()
