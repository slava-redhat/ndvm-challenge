import sys
import unittest
from pathlib import Path
from string import Template


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


if __name__ == "__main__":
    unittest.main()
