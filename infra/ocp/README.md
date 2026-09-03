# NDVM on OpenShift (trial / Developer Sandbox)

Deploys the same stack as `infra/gcp/` (postgres+pgvector, ollama, orchestrator,
ui) to an existing OpenShift project — e.g.
`rh-ee-swasserm-dev` on a trial cluster like
`console-openshift-console.apps.rm2.thpm.p1.openshiftapps.com`.

Differences from the GKE deployment (`infra/gcp/gke.py`):

| GKE                                   | OpenShift                                    |
|----------------------------------------|-----------------------------------------------|
| `gcloud container clusters create`     | not needed — trial project is pre-provisioned |
| Cloud Build + Artifact Registry        | `BuildConfig` (binary Docker build) + `ImageStream`, pushed to the project's internal registry |
| `Ingress` (nginx)                      | `Route` (one per path, since Route paths are prefix-only) |
| fixed `runAsUser: 1000` / `fsGroup: 1000` | no fixed UID — the default `restricted` SCC assigns one automatically |
| —                                       | ollama's `$HOME` (`/root`) relocated via `HOME=/data` — its default home dir isn't reachable under an arbitrary UID |

## 0. Prerequisites

- `oc` CLI installed and logged in: on the console, top-right → **Copy login
  command** → paste the `oc login --token=... --server=...` command.
- `.env` in the repo root (copy from `.env.example`). For a trial project
  without GCP/Vertex access, set the OpenAI tier instead of Vertex:
  ```
  NDVM_LLM_PROVIDER=openai
  OPENAI_API_KEY=sk-...
  ```
  (leave `GOOGLE_APPLICATION_CREDENTIALS`/Vertex vars unset — the orchestrator
  Deployment mounts that secret as optional).
- Select your project: `oc project rh-ee-swasserm-dev` (or set `OCP_NAMESPACE`).

## 1. Bootstrap (one-time)

```
python3 infra/ocp/openshift.py bootstrap
```

Creates the `ndvm` ServiceAccount and the `orchestrator`/`ui` ImageStreams +
BuildConfigs. No SCC grant is needed by default — postgres (built on the
official image, which already supports OpenShift's arbitrary-UID model via
nss_wrapper) and ollama (fixed here by pointing `$HOME` at the PVC mount
instead of `/root`) both run fine under the default `restricted` SCC.

If a pod still fails with a permission error on your specific cluster (some
clusters have non-standard SCC/fsGroup config), you can grant `anyuid` as a
troubleshooting escape hatch — requires project-admin rights:
```
python3 infra/ocp/openshift.py grant-anyuid
```

## 2. Deploy

```
python3 infra/ocp/openshift.py deploy
```

This:
1. Builds `orchestrator` and `ui` images via `oc start-build --from-dir=... --follow` (binary build — no git push/webhook needed, just your local checkout).
2. Syncs secrets/configmaps (`ndvm-secrets` from `.env`, `ndvm-postgres-init` from `db/schema.sql`, `ndvm-account-data` from `data/accounts/`, optional `ndvm-google-credentials`).
3. Applies postgres/ollama StatefulSets and waits for rollout.
4. Applies the orchestrator/ui Deployments (image-triggers pick up the freshly built images automatically) and Routes.
5. Prints the Route URLs.

## Restore an existing DB dump

The dump format is plain `pg_dump` gzip'd SQL — the same file works whether
it was created for GCP or here. Reuse `infra/gcp/backups/ndvm-vector.sql.gz` (or
create a fresh one from your local podman-compose stack), via the repo-root
`make` targets (`TARGET=ocp` selects this script and `infra/ocp/backups/`):
```
make vector-db-restore TARGET=ocp VECTOR_DB_BACKUP=infra/gcp/backups/ndvm-vector.sql.gz
# or, to make a new backup from your local stack first:
make vector-db-backup TARGET=ocp
make vector-db-restore TARGET=ocp
```
This scales `orchestrator` to 0, streams the dump into the `postgres-0` pod
via `oc exec`, then restores the original replica count.

## Other commands

```
python3 infra/ocp/openshift.py sync-secrets   # re-sync .env / data/accounts / schema.sql without rebuilding
python3 infra/ocp/openshift.py routes         # print route URLs
python3 infra/ocp/openshift.py teardown --yes # delete all NDVM resources in the project
```

## Storage quota

Trial/sandbox projects usually carry small storage quotas. Defaults here are
conservative (`POSTGRES_STORAGE=5Gi`, `OLLAMA_STORAGE=2Gi`); override via
environment variables if your project's quota allows more:
```
POSTGRES_STORAGE=20Gi OLLAMA_STORAGE=5Gi python3 infra/ocp/openshift.py deploy
```
