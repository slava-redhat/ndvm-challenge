import sys
import unittest
from pathlib import Path
from string import Template
from unittest.mock import patch


GCP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GCP_DIR))

import gke  # noqa: E402


class OllamaManifestTest(unittest.TestCase):
    def test_ollama_manifests_render_for_each_tier(self) -> None:
        for tier in gke.TIERS:
            config = gke.Config("project", "us-central1", "us-central1-a",
                                "ndvm", "ndvm", "ndvm", tier)
            values = gke.render_values(config, "test")
            self.assertIn("OLLAMA_CPU_REQUEST", values)
            rendered = Template(
                (GCP_DIR / "k8s" / "ollama" / "statefulset.yaml").read_text()
            ).substitute(values)
            self.assertIn("image: ollama/ollama:0.12.10", rendered)
            self.assertIn("ollama pull \"$OLLAMA_EMBED_MODEL\"", rendered)


class DeployRolloutTest(unittest.TestCase):
    def test_deploy_restarts_orchestrator_and_ui(self) -> None:
        config = gke.Config("project", "us-central1", "us-central1-a",
                            "ndvm", "ndvm", "ndvm", "e2-standard-2")
        commands: list[list[str]] = []

        def record_kubectl(_config, args, **_kwargs):
            commands.append(args)
            return ""

        with (
            patch.object(gke, "require_tools"),
            patch.object(gke, "cluster_credentials"),
            patch.object(gke, "build_image"),
            patch.object(gke, "render_and_apply"),
            patch.object(gke, "create_secret_and_schema"),
            patch.object(gke, "print_ingress_address"),
            patch.object(gke, "kubectl", side_effect=record_kubectl),
        ):
            gke.deploy(config, "test")

        self.assertIn(["rollout", "restart", "deployment/orchestrator"], commands)
        self.assertIn(["rollout", "restart", "deployment/ui"], commands)


if __name__ == "__main__":
    unittest.main()
