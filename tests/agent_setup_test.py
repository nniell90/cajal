import importlib.util
import pathlib
import unittest
from unittest import mock


def load_setup_module():
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    module_path = repo_root / "agent" / "cajal-agent-setup.py"
    spec = importlib.util.spec_from_file_location("cajal_agent_setup", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


setup = load_setup_module()


class AgentSetupTests(unittest.TestCase):
    def test_render_env_content_includes_install_identity_fields(self):
        config = {
            "server": "http://127.0.0.1:4000",
            "site": "site-123",
            "password": "secret123",
            "poll_interval": "1.5",
            "insecure": "1",
            "install_id": "install-abc",
            "installed_at": "2026-02-25T10:00:00Z",
        }
        content = setup.render_env_content(config)
        self.assertIn("CAJAL_AGENT_INSTALL_ID=", content)
        self.assertIn("install-abc", content)
        self.assertIn("CAJAL_AGENT_INSTALLED_AT=", content)
        self.assertIn("2026-02-25T10:00:00Z", content)

    def test_generate_install_identity_returns_uuid_and_utc_timestamp(self):
        ident = setup.generate_install_identity()
        install_id = str(ident.get("install_id") or "")
        installed_at = str(ident.get("installed_at") or "")
        self.assertRegex(install_id, r"^[0-9a-fA-F-]{36}$")
        self.assertRegex(installed_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    @mock.patch.object(setup, "request_json")
    def test_verify_registration_sends_install_identity_metadata(self, request_json):
        request_json.side_effect = [
            {"token": "tok-1"},
            {"ok": True},
        ]
        ok, message = setup.verify_registration(
            {
                "server": "http://127.0.0.1:4000",
                "site": "site-123",
                "password": "secret123",
                "insecure": "0",
                "install_id": "install-abc",
                "installed_at": "2026-02-25T10:00:00Z",
            }
        )
        self.assertTrue(ok)
        self.assertIn("verified", message.lower())

        first_payload = request_json.call_args_list[0].kwargs.get("payload") or {}
        agent_payload = first_payload.get("agent") or {}
        self.assertEqual(agent_payload.get("installId"), "install-abc")
        self.assertEqual(agent_payload.get("installedAt"), "2026-02-25T10:00:00Z")


if __name__ == "__main__":
    unittest.main()
