import importlib.util
import pathlib
import unittest
from unittest import mock


def load_agent_module():
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    module_path = repo_root / "agent" / "cajal-linux-agent.py"
    spec = importlib.util.spec_from_file_location("cajal_linux_agent", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


agent = load_agent_module()


class AgentCoreTests(unittest.TestCase):
    def test_safe_host_accepts_simple_host_and_rejects_bad_chars(self):
        self.assertEqual(agent.safe_host("example.com"), "example.com")
        self.assertEqual(agent.safe_host(""), "")
        self.assertEqual(agent.safe_host("bad host"), "")
        self.assertEqual(agent.safe_host("bad;rm"), "")

    def test_parse_speedtest_json_supports_ookla_and_speedtest_cli_shapes(self):
        down, up = agent.parse_speedtest_json('{"download":{"bandwidth":12500000},"upload":{"bandwidth":5000000}}')
        self.assertEqual(down, 100.0)
        self.assertEqual(up, 40.0)

        down2, up2 = agent.parse_speedtest_json('{"download":50000000,"upload":10000000}')
        self.assertEqual(down2, 50.0)
        self.assertEqual(up2, 10.0)
        self.assertEqual(
            agent.parse_speedtest_public_ip('{"interface":{"externalIp":"203.0.113.10"}}'),
            "203.0.113.10",
        )
        self.assertEqual(
            agent.parse_speedtest_public_ip('{"client":{"ip":"198.51.100.44"}}'),
            "198.51.100.44",
        )
        nslookup_style = (
            "Server:\tresolver1.opendns.com\n"
            "Address:\t208.67.222.222#53\n\n"
            "Non-authoritative answer:\n"
            "Name:\tmyip.opendns.com\n"
            "Address:\t93.184.216.34\n"
        )
        self.assertEqual(agent.parse_public_ipv4_from_text(nslookup_style), "93.184.216.34")

    def test_safe_update_url_rejects_unsafe_inputs(self):
        self.assertEqual(agent.safe_update_url("http://host/pkg.deb"), "http://host/pkg.deb")
        self.assertEqual(agent.safe_update_url("https://host/pkg.deb"), "https://host/pkg.deb")
        self.assertEqual(agent.safe_update_url("ftp://host/pkg.deb"), "")
        self.assertEqual(agent.safe_update_url("http://host/pkg.deb bad"), "")
        self.assertEqual(agent.safe_update_url(""), "")

    def test_execute_remote_command_rejects_unknown_command(self):
        result = agent.execute_remote_command("totally-unknown-command")
        self.assertFalse(result["ok"])
        self.assertEqual(result["exitCode"], 1)
        self.assertIn("Unsupported agent command", result["lines"][0])

    @mock.patch.object(agent, "run_exec_candidates")
    def test_execute_remote_command_supports_ipconfig(self, run_exec_candidates):
        run_exec_candidates.return_value = {
            "ok": True,
            "exit_code": 0,
            "cmdline": "ip -brief address",
            "stdout": "lo UNKNOWN 127.0.0.1/8",
            "stderr": "",
        }
        result = agent.execute_remote_command("ipconfig")
        self.assertTrue(result["ok"])
        self.assertEqual(result["exitCode"], 0)
        self.assertTrue(any("ipconfig" in line.lower() for line in result["lines"]))

    @mock.patch.object(agent, "run_exec_candidates")
    def test_run_speedtest_falls_back_when_primary_backend_fails(self, run_exec_candidates):
        run_exec_candidates.side_effect = [
            {
                "ok": False,
                "exit_code": 1,
                "cmdline": "speedtest --accept-license --accept-gdpr --format=json",
                "stdout": "",
                "stderr": "cannot change apparmor hat: Operation not permitted",
            },
            {
                "ok": True,
                "exit_code": 0,
                "cmdline": "speedtest-cli --json",
                "stdout": '{"download":50000000,"upload":10000000,"client":{"ip":"198.51.100.44"}}',
                "stderr": "",
            },
            {
                "ok": True,
                "exit_code": 0,
                "cmdline": "ping -c 3 -W 1 8.8.8.8",
                "stdout": "rtt min/avg/max/mdev = 10.2/11.8/13.4/0.9 ms",
                "stderr": "",
            },
        ]

        payload = agent.run_speedtest("8.8.8.8")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["exitCode"], 0)
        self.assertEqual(payload["metrics"]["speedtest"]["downloadMbps"], 50.0)
        self.assertEqual(payload["metrics"]["speedtest"]["uploadMbps"], 10.0)
        self.assertEqual(payload["metrics"]["speedtest"]["latencyMs"], 11.8)
        self.assertEqual(payload["metrics"]["speedtest"]["publicIp"], "198.51.100.44")
        self.assertTrue(
            any("speedtest backend: speedtest-cli --json" in line.lower() for line in payload["lines"]),
            msg=f"Expected backend line in output, got: {payload['lines']}",
        )
        self.assertTrue(
            any("public_ip=198.51.100.44" in line.lower() for line in payload["lines"]),
            msg=f"Expected public_ip line in output, got: {payload['lines']}",
        )

    @mock.patch.object(agent, "run_exec_candidates")
    def test_run_speedtest_auth_required_returns_latency_with_guidance(self, run_exec_candidates):
        run_exec_candidates.side_effect = [
            {
                "ok": False,
                "exit_code": 1,
                "cmdline": "speedtest --accept-license --accept-gdpr --format=json",
                "stdout": "",
                "stderr": "authentication required",
            },
            {
                "ok": False,
                "exit_code": 127,
                "cmdline": "speedtest-cli --json",
                "stdout": "",
                "stderr": "speedtest-cli: not found",
            },
            {
                "ok": True,
                "exit_code": 0,
                "cmdline": "ping -c 3 -W 1 8.8.8.8",
                "stdout": "rtt min/avg/max/mdev = 8.1/9.2/10.4/0.5 ms",
                "stderr": "",
            },
        ]

        payload = agent.run_speedtest("8.8.8.8")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["exitCode"], 0)
        self.assertIsNone(payload["metrics"]["speedtest"]["downloadMbps"])
        self.assertIsNone(payload["metrics"]["speedtest"]["uploadMbps"])
        self.assertEqual(payload["metrics"]["speedtest"]["latencyMs"], 9.2)
        self.assertEqual(payload["metrics"]["speedtest"]["publicIp"], "")
        self.assertTrue(
            any("needs speedtest auth" in line.lower() for line in payload["lines"]),
            msg=f"Expected auth guidance in lines, got: {payload['lines']}",
        )

    @mock.patch.object(agent, "run_exec_candidates")
    def test_run_publicip_uses_dns_probe_and_returns_public_ip_metric(self, run_exec_candidates):
        run_exec_candidates.return_value = {
            "ok": True,
            "exit_code": 0,
            "cmdline": "dig +short myip.opendns.com @resolver1.opendns.com",
            "stdout": "93.184.216.34\n",
            "stderr": "",
        }

        payload = agent.run_publicip()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["exitCode"], 0)
        self.assertEqual(payload["metrics"]["publicIp"], "93.184.216.34")
        self.assertTrue(
            any("public_ip=93.184.216.34" in line.lower() for line in payload["lines"]),
            msg=f"Expected public_ip line in output, got: {payload['lines']}",
        )

    def test_score_local_ipv4_candidate_prefers_physical_interfaces(self):
        physical = agent.score_local_ipv4_candidate("192.168.1.50", "enp3s0")
        docker = agent.score_local_ipv4_candidate("172.18.0.1", "docker0")
        self.assertGreater(physical, docker)

    @mock.patch.object(agent.socket, "getaddrinfo", return_value=[])
    @mock.patch.object(agent, "list_linux_global_ipv4_candidates")
    @mock.patch.object(agent, "probe_linux_route_source")
    @mock.patch.object(agent.socket, "socket")
    def test_detect_primary_local_ipv4_avoids_docker_bridge_when_nic_ip_exists(
        self,
        socket_ctor,
        probe_linux_route_source,
        list_linux_global_ipv4_candidates,
        _getaddrinfo,
    ):
        probe_linux_route_source.side_effect = [("172.18.0.1", "docker0"), ("172.18.0.1", "docker0")]
        list_linux_global_ipv4_candidates.return_value = [
            ("172.18.0.1", "docker0"),
            ("192.168.1.50", "enp3s0"),
        ]
        fake_sock = mock.Mock()
        fake_sock.getsockname.return_value = ("172.18.0.1", 0)
        socket_ctor.return_value = fake_sock

        chosen = agent.detect_primary_local_ipv4()
        self.assertEqual(chosen, "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
