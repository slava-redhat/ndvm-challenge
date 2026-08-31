#!/usr/bin/env python3
"""Deploy NDVM to an existing OpenShift project (e.g. a Developer Sandbox /
trial cluster) without shell wrappers.

Unlike gcp/gke.py, this script does NOT provision cluster infrastructure
(nodes, registries) — trial/sandbox OpenShift projects are pre-provisioned
for you. It targets an existing project, builds images with OpenShift
BuildConfigs (binary Docker-strategy builds pushed straight from your
checkout into the project's internal registry via an ImageStream), and
applies Deployments/StatefulSets/Routes.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from string import Template


ROOT = Path(__file__).resolve().parents[1]
OCP_DIR = ROOT / "ocp"
K8S_DIR = OCP_DIR / "k8s"

# Conservative defaults sized for a shared trial/sandbox project (small quota).
# Override any of these via environment variables of the same name, e.g.
# ORCHESTRATOR_CPU_LIMIT=1000m.
DEFAULT_RESOURCES = {
    "postgres": ("50m", "256Mi", "500m", "512Mi"),
    "ollama": ("250m", "512Mi", "1000m", "1Gi"),
    "orchestrator": ("50m", "256Mi", "500m", "1Gi"),
    "ui": ("50m", "256Mi", "500m", "512Mi"),
}
DEFAULT_POSTGRES_STORAGE = "5Gi"
DEFAULT_OLLAMA_STORAGE = "2Gi"


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


def exists(args: list[str]) -> bool:
    return subprocess.run(args, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


@dataclass(frozen=True)
class Config:
    namespace: str
    route_host: str

    @classmethod
    def from_environment(cls) -> "Config":
        namespace = os.environ.get("OCP_NAMESPACE")
        if not namespace:
            namespace = command(["oc", "project", "-q"], capture=True).strip()
        if not namespace:
            raise SystemExit(
                "Set OCP_NAMESPACE or `oc project <name>` to select your project first."
            )
        return cls(
            namespace=namespace,
            route_host=os.environ.get("OCP_ROUTE_HOST", ""),
        )


def oc(config: Config, args: list[str], **kwargs: object) -> str:
    return command(["oc", "-n", config.namespace, *args], **kwargs)


def check_login() -> None:
    require_tools("oc")
    if not exists(["oc", "whoami"]):
        raise SystemExit(
            "Not logged in. Run the 'oc login --token=... --server=...' command "
            "from the OpenShift console (top-right \u2192 Copy login command)."
        )


def render_values(config: Config, tag: str) -> dict[str, str]:
    values = {
        "NAMESPACE": config.namespace,
        "TAG": tag,
        "ROUTE_HOST": config.route_host,
        "POSTGRES_STORAGE": os.environ.get("POSTGRES_STORAGE", DEFAULT_POSTGRES_STORAGE),
        "OLLAMA_STORAGE": os.environ.get("OLLAMA_STORAGE", DEFAULT_OLLAMA_STORAGE),
    }
    for service, (cpu_request, memory_request, cpu_limit, memory_limit) in DEFAULT_RESOURCES.items():
        prefix = service.upper()
        values.update({
            f"{prefix}_CPU_REQUEST": os.environ.get(f"{prefix}_CPU_REQUEST", cpu_request),
            f"{prefix}_MEMORY_REQUEST": os.environ.get(f"{prefix}_MEMORY_REQUEST", memory_request),
            f"{prefix}_CPU_LIMIT": os.environ.get(f"{prefix}_CPU_LIMIT", cpu_limit),
            f"{prefix}_MEMORY_LIMIT": os.environ.get(f"{prefix}_MEMORY_LIMIT", memory_limit),
        })
    return values


def render_and_apply(config: Config, tag: str = "latest",
                     only: set[str] | None = None) -> None:
    values = render_values(config, tag)
    with tempfile.TemporaryDirectory(prefix="ndvm-ocp-") as temp_dir:
        output = Path(temp_dir)
        manifests = sorted(p for p in K8S_DIR.rglob("*.yaml") if p.name != "project.yaml")
        for source in manifests:
            relative = source.relative_to(K8S_DIR)
            if only and relative.name not in only:
                continue
            rendered = Template(source.read_text(encoding="utf-8")).substitute(values)
            if not values["ROUTE_HOST"]:
                # Drop empty `host:` lines so OpenShift auto-assigns the
                # <name>-<namespace>.apps.<cluster-domain> hostname.
                rendered = re.sub(r"^\s*host:\s*\n", "", rendered, flags=re.MULTILINE)
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8")
        for manifest in sorted(output.rglob("*.yaml")):
            command(["oc", "apply", "-f", str(manifest)])


def grant_anyuid(config: Config) -> None:
    """Not needed by default: postgres/ollama were verified to work under
    OpenShift's default 'restricted' SCC (arbitrary UID + auto-injected
    fsGroup) without any elevated grant. Kept as an opt-in escape hatch for
    clusters with non-standard SCC/fsGroup config — run manually via
    `python3 ocp/openshift.py grant-anyuid` only if postgres/ollama pods
    fail with permission errors after a normal deploy."""
    command(["oc", "adm", "policy", "add-scc-to-user", "anyuid",
              "-z", "ndvm", "-n", config.namespace])


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
            "oc", "-n", config.namespace, "create", "secret", "generic",
            "ndvm-secrets", f"--from-env-file={secret_file.name}",
            "--dry-run=client", "-o", "yaml",
        ], capture=True)
    oc(config, ["apply", "-f", "-"], input_text=secret)


def sync_google_credentials(config: Config) -> None:
    """Optional: only needed if NDVM_LLM_PROVIDER=vertex (the default). For a
    trial project without GCP/Vertex access, switch to the OpenAI tier
    instead (NDVM_LLM_PROVIDER=openai + OPENAI_API_KEY in .env) and skip
    this — the orchestrator Deployment mounts this secret as `optional`."""
    credentials_file = ROOT / ".application_default_credentials.json"
    if not credentials_file.is_file():
        print("No .application_default_credentials.json found; skipping "
              "(fine if using NDVM_LLM_PROVIDER=openai).")
        return
    credentials = command([
        "oc", "-n", config.namespace, "create", "secret", "generic",
        "ndvm-google-credentials",
        f"--from-file=application_default_credentials.json={credentials_file}",
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    oc(config, ["apply", "-f", "-"], input_text=credentials)


def sync_account_data(config: Config) -> None:
    accounts_dir = ROOT / "data" / "accounts"
    account_files = sorted(accounts_dir.glob("*.json"))
    if not account_files:
        raise SystemExit(f"No account data files found in {accounts_dir}.")
    account_data = command([
        "oc", "-n", config.namespace, "create", "configmap", "ndvm-account-data",
        *[f"--from-file={path.name}={path}" for path in account_files],
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    oc(config, ["apply", "-f", "-"], input_text=account_data)


def create_secrets_and_schema(config: Config) -> None:
    sync_secret(config)
    sync_google_credentials(config)
    sync_account_data(config)
    schema = command([
        "oc", "-n", config.namespace, "create", "configmap", "ndvm-postgres-init",
        f"--from-file=schema.sql={ROOT / 'db' / 'schema.sql'}",
        "--dry-run=client", "-o", "yaml",
    ], capture=True)
    oc(config, ["apply", "-f", "-"], input_text=schema)


def build_image(config: Config, service: str, tag: str) -> None:
    oc(config, ["start-build", service, f"--from-dir={ROOT / service}",
                "--follow", "--wait"])


def print_route_urls(config: Config) -> None:
    hosts = oc(config, ["get", "routes", "-o",
               "jsonpath={range .items[*]}{.metadata.name}{\"=\"}{.spec.host}{\"\\n\"}{end}"],
               capture=True)
    print("Routes:")
    for line in hosts.strip().splitlines():
        name, _, host = line.partition("=")
        print(f"  https://{host}  ({name})")


def bootstrap(config: Config) -> None:
    """One-time setup: service account + image streams/build configs.
    Safe to re-run."""
    check_login()
    render_and_apply(config, only={"serviceaccount.yaml"})
    render_and_apply(config, only={"imagestream.yaml", "buildconfig.yaml"})


def deploy(config: Config, tag: str) -> None:
    check_login()
    for service in ("orchestrator", "ui"):
        build_image(config, service, tag)

    create_secrets_and_schema(config)
    render_and_apply(config, tag, only={"service.yaml", "statefulset.yaml", "configmap.yaml"})
    for statefulset in ("postgres", "ollama"):
        oc(config, ["rollout", "status", f"statefulset/{statefulset}", "--timeout=600s"])

    render_and_apply(config, tag, only={"deployment.yaml"})
    render_and_apply(config, tag, only={"routes.yaml"})
    for deployment in ("orchestrator", "ui"):
        oc(config, ["rollout", "status", f"deployment/{deployment}", "--timeout=180s"])
    print_route_urls(config)


def sync_deployment_secrets(config: Config) -> None:
    check_login()
    create_secrets_and_schema(config)
    oc(config, ["rollout", "restart", "deployment/orchestrator"])
    oc(config, ["rollout", "status", "deployment/orchestrator", "--timeout=180s"])


def teardown(config: Config, confirmed: bool) -> None:
    if not confirmed:
        raise SystemExit("Refusing teardown. Re-run with teardown --yes.")
    check_login()
    for kind in ("route", "deployment", "statefulset", "service", "configmap",
                 "secret", "buildconfig", "imagestream", "pvc"):
        command(["oc", "-n", config.namespace, "delete", kind, "--all",
                  "--ignore-not-found=true"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    subcommands.add_parser("bootstrap", help="Service account, SCC grant, image streams/build configs")
    deploy_parser = subcommands.add_parser("deploy", help="Build images and deploy NDVM")
    deploy_parser.add_argument("--tag", default="latest")
    subcommands.add_parser("sync-secrets", help="Update secrets/configmaps from .env and data/")
    subcommands.add_parser("routes", help="Print the NDVM route URLs")
    subcommands.add_parser("grant-anyuid", help="Troubleshooting only: grant anyuid SCC (needs project admin)")
    teardown_parser = subcommands.add_parser("teardown", help="Delete all NDVM resources in the project")
    teardown_parser.add_argument("--yes", action="store_true", help="Confirm destructive deletion")
    args = parser.parse_args()
    config = Config.from_environment()
    if args.action == "bootstrap":
        bootstrap(config)
    elif args.action == "deploy":
        deploy(config, args.tag)
    elif args.action == "sync-secrets":
        sync_deployment_secrets(config)
    elif args.action == "routes":
        check_login()
        print_route_urls(config)
    elif args.action == "grant-anyuid":
        check_login()
        grant_anyuid(config)
    else:
        teardown(config, args.yes)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
