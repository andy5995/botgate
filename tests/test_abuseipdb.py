"""Focused standard-library tests for the managed feed and access ordering."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import botgate_proxy as botgate


def source_body(*ips):
    return ("# Number of ips: {}\n".format(len(ips)) +
            "\n".join(ip + " # country ASN description" for ip in ips) + "\n").encode("utf-8")


class Response(io.BytesIO):
    def __init__(self, body, length=None, url=None, status=200):
        super().__init__(body)
        self.headers = {} if length is None else {"Content-Length": str(length)}
        self.url = url or botgate.AbuseIPDBFeed.URL
        self.status = status

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cfg = {"can_dir": str(self.root), "abuseipdb_update_hours": 12}
        self.cache = self.root / "abuseipdb.can"

    def feed(self, hours=12):
        cfg = dict(self.cfg, abuseipdb_update_hours=hours)
        feed = botgate.AbuseIPDBFeed(cfg)
        self.addCleanup(feed.stop)
        return feed

    def test_upstream_comments_and_duplicates(self):
        body = b"\xef\xbb\xbf; comment\n\n" + source_body("203.0.113.1", "203.0.113.1", "198.51.100.2")
        self.assertEqual(botgate.AbuseIPDBFeed.validate(body, require_count=True),
                         frozenset(("203.0.113.1", "198.51.100.2")))

    def test_reject_empty_html_malformed_ipv6_cidr_and_truncation(self):
        cases = [b"", b"# comments only\n", b"<html>Error</html>",
                 source_body("203.0.113.1", "invalid"), source_body("::1"),
                 source_body("203.0.113.0/24"), b"# Number of ips: 2\n203.0.113.1\n",
                 b"# Number of ips: 1\n# Number of ips: 1\n203.0.113.1\n",
                 b"203.0.113.1\n", b"\xff\xfe"]
        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValueError):
                botgate.AbuseIPDBFeed.validate(body, require_count=True)

    def test_old_cache_is_usable(self):
        self.cache.write_bytes(b"; Last successful update: 2000-01-01\n203.0.113.1\n")
        feed = self.feed()
        self.assertTrue(feed.contains("203.0.113.1"))
        self.assertFalse(feed.contains("198.51.100.2"))
        self.assertIsNone(feed._thread)

    def test_invalid_cache_does_not_stop_startup(self):
        self.cache.write_bytes(b"<html>broken</html>")
        with self.assertLogs(botgate.log, level="INFO") as captured:
            feed = self.feed()
        self.assertFalse(feed.contains("203.0.113.1"))
        self.assertIn("cache could not be loaded", captured.output[0])
        self.assertEqual(self.cache.read_bytes(), b"<html>broken</html>")

    def test_disabled_keeps_cache_and_does_not_download_or_filter(self):
        body = source_body("203.0.113.1")
        self.cache.write_bytes(body)
        feed = self.feed(0)
        with mock.patch.object(feed, "_download") as download:
            feed.start_updater()
            self.assertFalse(feed.refresh())
            download.assert_not_called()
        self.assertFalse(feed.contains("203.0.113.1"))
        self.assertIsNone(feed._thread)
        self.assertEqual(self.cache.read_bytes(), body)

    def test_refresh_replaces_and_logs_additions_and_removals(self):
        self.cache.write_bytes(source_body("203.0.113.1", "203.0.113.2"))
        feed = self.feed()
        with mock.patch.object(feed, "_download", return_value=source_body("203.0.113.2", "198.51.100.3")), \
                self.assertLogs(botgate.log, level="INFO") as captured:
            self.assertTrue(feed.refresh())
        self.assertFalse(feed.contains("203.0.113.1"))
        self.assertTrue(feed.contains("198.51.100.3"))
        self.assertIn("(+1 added, -1 removed)", captured.output[-1])
        self.assertEqual(captured.records[-1].levelname, "INFO")
        self.assertIn("AUTO-MANAGED", self.cache.read_text())
        self.assertEqual(botgate.AbuseIPDBFeed.validate(self.cache.read_bytes()),
                         frozenset(("203.0.113.2", "198.51.100.3")))
        self.assertEqual(list(self.root.glob(".abuseipdb-*.tmp")), [])

    def test_failed_download_validation_or_write_keeps_file_and_snapshot(self):
        original = source_body("203.0.113.1")
        self.cache.write_bytes(original)
        feed = self.feed()
        failures = [TimeoutError("connection timed out"), b"<html>unavailable</html>",
                    b"# Number of ips: 2\n198.51.100.2\n"]
        for failure in failures:
            with self.subTest(failure=failure):
                args = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with mock.patch.object(feed, "_download", **args), \
                        self.assertLogs(botgate.log, level="INFO") as captured:
                    self.assertFalse(feed.refresh())
                self.assertEqual(captured.records[-1].levelname, "INFO")
                self.assertIn("keeping previous list", captured.output[-1])
                self.assertEqual(self.cache.read_bytes(), original)
                self.assertTrue(feed.contains("203.0.113.1"))
        with mock.patch.object(feed, "_download", return_value=source_body("198.51.100.2")), \
                mock.patch.object(botgate.os, "replace", side_effect=PermissionError("write denied")), \
                self.assertLogs(botgate.log, level="INFO") as captured:
            self.assertFalse(feed.refresh())
        self.assertIn("write denied", captured.output[-1])
        self.assertEqual(self.cache.read_bytes(), original)
        self.assertTrue(feed.contains("203.0.113.1"))
        self.assertFalse(feed.contains("198.51.100.2"))
        self.assertEqual(list(self.root.glob(".abuseipdb-*.tmp")), [])

    def test_missing_cache_failure_has_no_fake_previous_list(self):
        feed = self.feed()
        with mock.patch.object(feed, "_download", side_effect=OSError("offline")), \
                self.assertLogs(botgate.log, level="INFO") as captured:
            self.assertFalse(feed.refresh())
        self.assertIn("no feed snapshot is active", captured.output[-1])
        self.assertFalse(self.cache.exists())

    def test_old_snapshot_remains_available_during_refresh(self):
        self.cache.write_bytes(source_body("203.0.113.1"))
        feed = self.feed()
        started, proceed = threading.Event(), threading.Event()

        def delayed_download():
            started.set()
            if not proceed.wait(2):
                raise TimeoutError("test timed out")
            return source_body("198.51.100.2")

        with mock.patch.object(feed, "_download", side_effect=delayed_download):
            worker = threading.Thread(target=feed.refresh, daemon=True)
            worker.start()
            try:
                self.assertTrue(started.wait(1))
                self.assertTrue(feed.contains("203.0.113.1"))
                self.assertFalse(feed.contains("198.51.100.2"))
            finally:
                proceed.set()
                worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertFalse(feed.contains("203.0.113.1"))
        self.assertTrue(feed.contains("198.51.100.2"))

    def test_one_immediate_daemon_updater_uses_hours_and_stops(self):
        feed = self.feed()
        waited = threading.Event()
        intervals = []
        real_wait = feed._stop.wait

        def record_wait(interval):
            intervals.append(interval)
            waited.set()
            return real_wait(interval)

        with mock.patch.object(feed, "refresh", return_value=True) as refresh, \
                mock.patch.object(feed._stop, "wait", side_effect=record_wait):
            feed.start_updater()
            self.assertTrue(waited.wait(1))
            first_thread = feed._thread
            feed.start_updater()
            self.assertIs(feed._thread, first_thread)
            self.assertTrue(first_thread.daemon)
            refresh.assert_called_once_with()
            self.assertEqual(intervals, [43200])
            feed.stop()
            self.assertFalse(first_thread.is_alive())

    def test_http_length_and_size_limits(self):
        feed = self.feed()
        body = source_body("203.0.113.1")
        with mock.patch.object(botgate.urllib.request, "urlopen", return_value=Response(body, len(body))) as opened:
            self.assertEqual(feed._download(), body)
        self.assertEqual(opened.call_args[1]["timeout"], 15)
        self.assertIn("BotGate", opened.call_args[0][0].get_header("User-agent"))
        for response in [Response(body, len(body) + 1), Response(body, feed.MAX_BYTES + 1),
                         Response(body, status=206), Response(body, url="http://example.test/feed")]:
            with self.subTest(response=response), \
                    mock.patch.object(botgate.urllib.request, "urlopen", return_value=response), \
                    self.assertRaises(ValueError):
                feed._download()
        with mock.patch.object(feed, "MAX_BYTES", 8), \
                mock.patch.object(botgate.urllib.request, "urlopen", return_value=Response(body)), \
                self.assertRaises(ValueError):
            feed._download()

    def test_failed_attempt_retries_on_next_scheduled_interval(self):
        feed = self.feed()
        intervals = []

        def simulated_wait(interval):
            intervals.append(interval)
            return len(intervals) == 2

        with mock.patch.object(feed, "_download", side_effect=[TimeoutError("offline"), source_body("203.0.113.1")]) as download, \
                mock.patch.object(feed._stop, "wait", side_effect=simulated_wait), \
                self.assertLogs(botgate.log, level="INFO") as captured:
            feed.start_updater()
            feed._thread.join(2)
        self.assertFalse(feed._thread.is_alive())
        self.assertEqual(download.call_count, 2)
        self.assertEqual(intervals, [43200, 43200])
        self.assertTrue(feed.contains("203.0.113.1"))
        self.assertIn("update failed: offline", "\n".join(captured.output))
        self.assertIn("abuseipdb.can updated:", "\n".join(captured.output))

    def test_http_deadline_and_shutdown_cancellation(self):
        feed = self.feed()
        body = source_body("203.0.113.1")
        with mock.patch.object(botgate.urllib.request, "urlopen", return_value=Response(body)), \
                mock.patch.object(botgate.time, "monotonic", side_effect=[0, 61]), \
                self.assertRaises(TimeoutError):
            feed._download()
        feed.stop()
        with mock.patch.object(botgate.urllib.request, "urlopen", return_value=Response(body)), \
                self.assertRaises(OSError):
            feed._download()


class ConfigAndAccessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "botgate_proxy.cfg"

    def write_config(self, value=None, extra=""):
        setting = "" if value is None else "abuseipdb update = {}\n".format(value)
        self.config.write_text("[proxy]\nlisten_port=23230\n" + setting + extra)

    def load_config(self):
        with mock.patch.object(botgate, "CONFIG_FILE", str(self.config)):
            return botgate.load_config()

    def test_interval_default_disable_and_shared_listeners(self):
        for value, expected in [(None, 12), ("12", 12), (" 24 ", 24), ("0", 0)]:
            with self.subTest(value=value):
                self.write_config(value, "[Listener2]\nlisten_port=2112\nabuseipdb update=99\n")
                listeners = self.load_config()
                self.assertEqual([x["abuseipdb_update_hours"] for x in listeners], [expected, expected])
                self.assertEqual([x["listen_port"] for x in listeners], [23230, 2112])

    def test_invalid_interval_has_clear_startup_error(self):
        for value in ["", "bananas", "-1", "1.5", "12hr", "9" * 100]:
            with self.subTest(value=value), contextlib.redirect_stdout(io.StringIO()) as output:
                self.write_config(value)
                with self.assertRaises(SystemExit):
                    self.load_config()
                self.assertIn("abuseipdb update must be a whole number", output.getvalue())

    def test_generated_and_sample_config_have_matching_guidance(self):
        sample = (Path(botgate.__file__).parent / "botgate_proxy.cfg").read_text()
        for config in (sample, botgate.DEFAULT_CONFIG):
            self.assertIn("abuseipdb update = 12", config)
            self.assertIn("0 = DISABLED", config)
            self.assertIn("; Updates and failures log at INFO", config)
        marker = "; Automatically maintain can_dir/abuseipdb.can"
        self.assertEqual(sample.split(marker)[1].split("abuseipdb update = 12")[0],
                         botgate.DEFAULT_CONFIG.split(marker)[1].split("abuseipdb update = 12")[0])

    def test_generated_config_and_relative_paths_work_from_other_cwd(self):
        with mock.patch.object(botgate, "CONFIG_FILE", str(self.config)), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                botgate.load_config()
        self.assertIn("abuseipdb update = 12", self.config.read_text())
        previous = os.getcwd()
        try:
            os.chdir(self.root)
            listeners = self.load_config()
        finally:
            os.chdir(previous)
        self.assertEqual(listeners[0]["can_dir"], str(Path(botgate.__file__).parent / "can"))
        self.assertEqual(listeners[0]["abuseipdb_update_hours"], 12)

    def blocks(self, hours=12):
        for name in ["ip.can", "ip-silent.can", "host.can", "ipfilter_exempt.cfg"]:
            (self.root / name).write_text("")
        geo = self.root / "geo"
        geo.mkdir(exist_ok=True)
        cfg = {"can_dir": str(self.root), "geo_dir": str(geo), "abuseipdb_update_hours": hours,
               "dns_lookup_enabled": True, "listen_port": 23230, "rate_limit_ban_minutes": 90}
        blocks = botgate.BlockLists(cfg)
        self.addCleanup(blocks.abuseipdb.stop)
        limiter = mock.Mock()
        limiter.is_banned.return_value = False
        limiter.record_and_check.return_value = False
        return cfg, blocks, limiter

    def test_feed_blocks_before_dns_rate_limit_gate_or_backend(self):
        (self.root / "abuseipdb.can").write_bytes(source_body("203.0.113.42"))
        cfg, blocks, limiter = self.blocks()
        client = mock.Mock()
        semaphore = threading.BoundedSemaphore(1)
        semaphore.acquire()
        with mock.patch.object(botgate.socket, "create_connection") as backend, \
                mock.patch.object(botgate, "run_gate") as gate, \
                mock.patch.object(botgate, "reverse_dns_lookup") as dns, \
                self.assertLogs(botgate.log, level="WARNING") as captured:
            botgate.handle_client(client, ("203.0.113.42", 1234), cfg, blocks, limiter, semaphore)
        backend.assert_not_called()
        gate.assert_not_called()
        dns.assert_not_called()
        limiter.record_and_check.assert_not_called()
        client.close.assert_called()
        self.assertEqual(captured.records[0].levelname, "WARNING")
        self.assertIn("[23230] 203.0.113.42 blocked by abuseipdb.can.", captured.output[0])
        self.assertTrue(semaphore.acquire(blocking=False))

    def test_exemption_wins_and_snapshot_is_shared(self):
        (self.root / "abuseipdb.can").write_bytes(source_body("203.0.113.42"))
        cfg, blocks, limiter = self.blocks()
        blocks.exempt = botgate.PatternList([botgate.Pattern("203.0.113.42")])
        for port in [23230, 2112]:
            listener = dict(cfg, listen_port=port)
            self.assertEqual(botgate.check_access("203.0.113.42", blocks, listener, limiter), ("exempt", None))
        limiter.is_banned.assert_not_called()
        limiter.record_and_check.assert_not_called()
        blocks.exempt = botgate.PatternList([])
        for port in [23230, 2112]:
            self.assertEqual(botgate.check_access("203.0.113.42", blocks, dict(cfg, listen_port=port), limiter),
                             ("block_logged", "abuseipdb.can"))

    def test_other_lists_dns_and_rate_limit_still_work(self):
        cfg, blocks, limiter = self.blocks()
        ip = "203.0.113.42"
        for pattern in [ip, "203.0.113.0/24", "203.0.113.*"]:
            blocks.ip_can = botgate.PatternList([botgate.Pattern(pattern)])
            self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("block_logged", "ip.can"))
        blocks.ip_can = botgate.PatternList([])
        blocks.ip_silent = botgate.PatternList([botgate.Pattern(ip)])
        self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("block_silent", "ip-silent.can"))
        blocks.ip_silent = botgate.PatternList([])
        (self.root / "geo" / "example.txt").write_text("deny from 203.0.113.0/24\n")
        blocks.geo["example.txt"] = botgate.load_geo_file(str(self.root / "geo" / "example.txt"))
        self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("block_logged", "geo/example.txt"))
        blocks.geo = {}
        with mock.patch.object(botgate, "reverse_dns_lookup") as dns:
            self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("allow", None))
            dns.assert_not_called()
        blocks.host_can = botgate.PatternList([botgate.Pattern("*.bad.test")])
        with mock.patch.object(botgate, "reverse_dns_lookup", return_value="scanner.bad.test"):
            self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter),
                             ("block_logged", "host.can (scanner.bad.test)"))
        with mock.patch.object(botgate, "reverse_dns_lookup", return_value=None):
            self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("allow", None))
        limiter.is_banned.return_value = True
        self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter), ("block_logged", "temp_ip.can"))
        limiter.is_banned.return_value = False
        blocks.host_can = botgate.PatternList([])
        limiter.record_and_check.return_value = True
        self.assertEqual(botgate.check_access(ip, blocks, cfg, limiter),
                         ("block_logged", "temp_ip.can (just triggered)"))

    def test_disabled_cached_ip_proceeds_to_other_checks(self):
        (self.root / "abuseipdb.can").write_bytes(source_body("203.0.113.42"))
        cfg, blocks, limiter = self.blocks(0)
        self.assertEqual(botgate.check_access("203.0.113.42", blocks, cfg, limiter), ("allow", None))
        limiter.record_and_check.assert_called_once_with("203.0.113.42")


if __name__ == "__main__":
    unittest.main()
