#!/usr/bin/env python3
"""Provision and operate the NDVM GKE deployment without shell wrappers."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from string import Template


ROOT = Path(__file__).resolve().parents[1]
GCP_DIR = ROOT / "gcp"
K8S_DIR = GCP_DIR / "k8s"

TIERS = {
    "e2-medium": {
        "postgres": ("25m", "128Mi", "500m", "512Mi"),
        "ollama": ("250m", "512Mi", "1000m", "1Gi"),
        "ingest": ("10m", "128Mi", "500m", "512Mi"),
        "orchestrator": ("10m", "256Mi", "500m", "1Gi"),
        "ui": ("10m", "128Mi", "500m", "512Mi"),
    },
    "e2-standard-2": {
        "postgres": ("100m", "256Mi", "1000m", "1Gi"),
        "ollama": ("500m", "1Gi", "2000m", "2Gi"),
        "ingest": ("50m", "256Mi", "500m", "1Gi"),
        "orchestrator": ("100m", "256Mi", "500m", "1Gi"),
        "ui": ("100m", "256Mi", "500m", "1Gi"),
    },
    "e2-standard-4": {
        "postgres": ("250m", "512Mi", "2000m", "2Gi"),
        "ollama": ("1000m", "1Gi", "4000m", "2Gi"),
        "ingest": ("100m", "512Mi", "1000m", "2Gi"),
        "orchestrator": ("250m", "512Mi", "1000m", "2Gi"),
        "ui": ("250m", "512Mi", "1000m", "2Gi"),
    },
}


def command(args: list[str], *, input_text: str | None = None,
            capture: bool = False) -> str:
    print("+", " ".join(args))
    completed = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout if capture else ""


def require_tools(*tools: str) -> None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"Missing required command(s): {', '.join(missing)}")


@dataclass(frozen=True)
class Config:
    project: str
    region: str
    zone: str
    cluster: str
    repository: str
    namespace: str
    tier: str

    @property
    def registry(self) -> str:
        return f"{self.region}-docker.pkg.dev/{self.project}/{self.repository}"

    @classmethod
    def from_environment(cls) -> "Config":
        project = os.environ.get("GCP_PROJECT_ID")
        if not project:
            project = command(["gcloud", "config", "get-value", "project"], capture=True).strip()
        if not project or project == "(unset)":
            raise SystemExit("Set GCP_PROJECT_ID or configure a default gcloud project.")
        tier = os.environ.get("GKE_MACHINE_TYPE", "e2-standard-2")
        if tier not in TIERS:
            raise SystemExit(f"Unsupported GKE_MACHINE_TYPE={tier}; choose: {', '.join(TIERS)}")
        region = os.environ.get("GCP_REGION", "us-central1")
        return cls(
            project=project,
            region=region,
            zone=os.environ.get("GCP_ZONE", f"{region}-a"),
            cluster=os.environ.get("GKE_CLUSTER_NAME", "ndvm"),
            repository=os.environ.get("ARTIFACT_REPOSITORY", "ndvm"),
            namespace=os.environ.get("K8S_NAMESPACE", "ndvm"),
            tier=tier,
        )


def kubectl(config: Config, args: list[str], **kwargs: object) -> str:
    return command(["kubectl", "-n", config.namespace, *args], **kwargs)


def cluster_credentials(config: Config) -> None:
    command([
        "gcloud", "container", "clusters", "get-credentials", config.cluster,
        "--zone", config.zone, "--project", config.project,
    ])


def exists(args: list[str]) -> bool:
    return subprocess.run(args, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


def provision(config: Config) -> None:
    require_tools("gcloud", "kubectl")
    command(["gcloud", "config", "set", "project", config.project])
    command([
        "gcloud", "services", "enable",
        "container.googleapis.com", "artifactregistry.googleapis.com",
        "cloudbuild.googleapis.com",
        "--project", config.project,
    ])

    if not exists(["gcloud", "artifacts", "repositories", "describe", config.repository,
                   "--location", config.region, "--project", config.project]):
        command([
            "gcloud", "artifacts", "repositories", "create", config.repository,
            "--repository-format", "docker", "--location", config.region,
            "--description", "NDVM container images", "--project", config.project,
        ])

    if not exists(["gcloud", "container", "clusters", "describe", config.cluster,
                   "--zone", config.zone, "--project", config.project]):
        command([
            "gcloud", "container", "clusters", "create", config.cluster,
            "--zone", config.zone, "--num-nodes", "1", "--machine-type", config.tier,
            "--disk-size", "30", "--disk-type", "pd-standard", "--enable-ip-alias",
            "--release-channel", "regular", "--project", config.project,
        ])

    cluster_credentials(config)
    render_and_apply(config, only={"namespace.yaml", "serviceaccount.yaml"})

    if not exists(["kubectl", "get", "namespace", "ingress-nginx"]):
        command([
            "kubectl", "apply", "-f",
            "https://raw.githubusercontent.com/kubernetes/ingress-nginx/"
            "controller-v1.12.1/deploy/static/provider/cloud/deploy.yaml",
        ])
        command([
            "kubectl", "wait", "--namespace", "ingress-nginx",
            "--for=condition=ready", "pod",
            "--selector=app.kubernetes.io/component=controller", "--timeout=180s",
        ])


def render_values(config: Config, tag: str) -> dict[str, str]:
    values = {
        "NAMESPACE": config.namespace,
        "REGISTRY": config.registry,
        "TAG": tag,
    }
    for service, (cpu_request, memory_request, cpu_limit, memory_limit) in TIERS[config.tier].items():
        prefix = service.upper()
        values.update({
            f"{prefix}_CPU_REQUEST": cpu_request,
            f"{prefix}_MEMORY_REQUEST": memory_request,
            f"{prefix}_CPU_LIMIT": cpu_limit,
            f"{prefix}_MEMORY_LIMIT": memory_limit,
        })
    return values


def render_and_apply(config: Config, tag: str = "latest",
                     only: set[str] | None = None) -> None:
    values = render_values(config, tag)
    with tempfile.TemporaryDirectory(prefix="ndvm-k8s-") as temp_dir:
        output = Path(temp_dir)
        manifests = sorted(K8S_DIR.rglob("*.yaml"))
        for source in manifests:
            relative = source.relative_to(K8S_DIR)
            if only and relative.name not in only:
                continue
            rendered = Template(source.read_text(encoding="utf-8")).substitute(values)
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8")
        for manifest in sorted(output.rglob("*.yaml")):
            command(["kubectl", "apply", "-f", str(manifest)])


def sync_secret(config: Config) -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        raise SystemExit("Create .env from .env.example before deployment.")
    excluded_prefixes = ("OLLAMA_", "INGEST_")
    filtered = []
    for line in env_file.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0].strip()
        if (not key or key.startswith("#") or key.endswith("_CREDENTIALS")
                or key.startswith(excluded_prefixes)):
            continue
        filtered.append(line)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as secret_file:
        secret_file.write("\n".join(filtered) + "\n")
        secret_file.flush()
        secret = command([
            "kubectl", "-n", config.namespace, "create", "secret", "generic",
            "ndvm-secrets", f"--from-env-file={secret_file.name}",
            "--dry-run=client", "-o", "yaml",
        ], capture=True)
    kubectl(config, ["apply", "-f", "-"], input_text=secret)


def sync_google_credentials(config: Config) -> None:
    credentials_file = ROOT / ".application_default_credentials.json"
    if not credentials_file.is_file():
        raise SystemExit(
            "Missing .application_default_credentials.json required for Vertex authentication."
        )
    credentials = command([
        "kubectl", "-n", config.namespace, "create", "secret", "generic",
        "ndvm-google-credentials",
        f"--from-file=application_default_credentials.json={credentials_file}",
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    kubectl(config, ["apply", "-f", "-"], input_text=credentials)


def sync_account_data(config: Config) -> None:
    accounts_dir = ROOT / "data" / "accounts"
    account_files = sorted(accounts_dir.glob("*.json"))
    if not account_files:
        raise SystemExit(f"No account data files found in {accounts_dir}.")
    account_data = command([
        "kubectl", "-n", config.namespace, "create", "configmap", "ndvm-account-data",
        *[f"--from-file={path.name}={path}" for path in account_files],
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    kubectl(config, ["apply", "-f", "-"], input_text=account_data)


def create_secret_and_schema(config: Config) -> None:
    sync_secret(config)
    sync_google_credentials(config)
    sync_account_data(config)
    schema = command([
        "kubectl", "-n", config.namespace, "create", "configmap", "ndvm-postgres-init",
        f"--from-file=schema.sql={ROOT / 'db' / 'schema.sql'}",
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    kubectl(config, ["apply", "-f", "-"], input_text=schema)


def build_image(config: Config, service: str, tag: str) -> None:
    command([
        "gcloud", "builds", "submit", str(ROOT / service),
        f"--config={GCP_DIR / f'cloudbuild-{service}.yaml'}",
        f"--substitutions=_TAG={config.registry}/{service}:{tag}",
        f"--project={config.project}", "--suppress-logs",
    ])


def print_ingress_address(config: Config, wait: bool = False) -> None:
    deadline = time.monotonic() + 300 if wait else 0
    while True:
        address = kubectl(
            config,
            ["get", "ingress", "ndvm", "-o",
             "jsonpath={.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}"],
            capture=True,
        ).strip()
        if address:
            print(f"NDVM is available at http://{address}/")
            return
        if not wait or time.monotonic() >= deadline:
            print("Ingress address is pending. Run `python3 gcp/gke.py ingress --wait`.")
            return
        print("Waiting for ingress address...")
        time.sleep(10)


def deploy(config: Config, tag: str) -> None:
    require_tools("gcloud", "kubectl")
    cluster_credentials(config)
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(build_image, config, service, tag)
                   for service in ("orchestrator", "ui")]
        for future in futures:
            future.result()

    render_and_apply(config, tag, only={"namespace.yaml", "serviceaccount.yaml"})
    create_secret_and_schema(config)
    render_and_apply(config, tag, only={"service.yaml", "statefulset.yaml"})
    for statefulset in ("postgres", "ollama"):
        kubectl(config, ["rollout", "status", f"statefulset/{statefulset}", "--timeout=600s"])

    render_and_apply(config, tag, only={"deployment.yaml", "ingress.yaml"})
    for deployment in ("orchestrator", "ui"):
        if deployment == "orchestrator":
            kubectl(config, ["rollout", "restart", f"deployment/{deployment}"])
        kubectl(config, ["rollout", "status", f"deployment/{deployment}", "--timeout=180s"])
    print_ingress_address(config)


def sync_deployment_secrets(config: Config) -> None:
    require_tools("gcloud", "kubectl")
    cluster_credentials(config)
    sync_secret(config)
    sync_google_credentials(config)
    sync_account_data(config)
    kubectl(config, ["rollout", "restart", "deployment/orchestrator"])
    kubectl(config, ["rollout", "status", "deployment/orchestrator", "--timeout=180s"])


def teardown(config: Config, confirmed: bool) -> None:
    if not confirmed:
        raise SystemExit("Refusing teardown. Re-run with teardown --yes.")
    require_tools("gcloud")
    if exists(["gcloud", "container", "clusters", "describe", config.cluster,
               "--zone", config.zone, "--project", config.project]):
        command([
            "gcloud", "container", "clusters", "delete", config.cluster,
            "--zone", config.zone, "--project", config.project, "--quiet",
        ])
    if exists(["gcloud", "artifacts", "repositories", "describe", config.repository,
               "--location", config.region, "--project", config.project]):
        command([
            "gcloud", "artifacts", "repositories", "delete", config.repository,
            "--location", config.region, "--project", config.project, "--quiet",
        ])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    subcommands.add_parser("provision", help="Create GKE and Artifact Registry")
    deploy_parser = subcommands.add_parser("deploy", help="Build images and deploy NDVM")
    deploy_parser.add_argument("--tag", default="latest")
    subcommands.add_parser("sync-secrets", help="Update Kubernetes secrets from .env")
    ingress_parser = subcommands.add_parser("ingress", help="Print the NDVM ingress URL")
    ingress_parser.add_argument("--wait", action="store_true",
                                help="Wait up to five minutes for an ingress address")
    teardown_parser = subcommands.add_parser("teardown", help="Delete all NDVM GCP resources")
    teardown_parser.add_argument("--yes", action="store_true", help="Confirm destructive deletion")
    args = parser.parse_args()
    config = Config.from_environment()
    if args.action == "provision":
        provision(config)
    elif args.action == "deploy":
        deploy(config, args.tag)
    elif args.action == "sync-secrets":
        sync_deployment_secrets(config)
    elif args.action == "ingress":
        require_tools("gcloud", "kubectl")
        cluster_credentials(config)
        print_ingress_address(config, args.wait)
    else:
        teardown(config, args.yes)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
