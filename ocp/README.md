# NDVM on OpenShift (trial / Developer Sandbox)

Deploys the same stack as `gcp/` (postgres+pgvector, ollama, orchestrator,
ui) to an existing OpenShift project — e.g.
`rh-ee-swasserm-dev` on a trial cluster like
`console-openshift-console.apps.rm2.thpm.p1.openshiftapps.com`.

Differences from the GKE deployment (`gcp/gke.py`):

| GKE                                   | OpenShift                                    |
|----------------------------------------|-----------------------------------------------|
| `gcloud container clusters create`     | not needed — trial project is pre-provisioned |
| Cloud Build + Artifact Registry        | `BuildConfig` (binary Docker build) + `ImageStream`, pushed to the project's internal registry |
| `Ingress` (nginx)                      | `Route` (one per path, since Route paths are prefix-only) |
| fixed `runAsUser: 1000` / `fsGroup: 1000` | no fixed UID — the default `restricted` SCC assigns one automatically |
| —                                       | `anyuid` SCC grant required for the upstream postgres/ollama images (see below) |

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
python3 ocp/openshift.py bootstrap
```

Creates the `ndvm` ServiceAccount, grants it the `anyuid` SCC (required
because `pgvector/pgvector:pg16` and `ollama/ollama` are upstream images that
hard-require UID 999/root and can't run under OpenShift's default
arbitrary-UID SCC — see `ocp/k8s/serviceaccount-scc-anyuid.md`), and creates
the `orchestrator`/`ui` ImageStreams + BuildConfigs.

If `anyuid` grant fails with a permissions error, your trial account may not
have `admin` on the project — ask whoever provisioned it, or run the command
manually as an admin:
```
oc adm policy add-scc-to-user anyuid -z ndvm -n <namespace>
```

## 2. Deploy

```
python3 ocp/openshift.py deploy
```

This:
1. Builds `orchestrator` and `ui` images via `oc start-build --from-dir=... --follow` (binary build — no git push/webhook needed, just your local checkout).
2. Syncs secrets/configmaps (`ndvm-secrets` from `.env`, `ndvm-postgres-init` from `db/schema.sql`, `ndvm-account-data` from `data/accounts/`, optional `ndvm-google-credentials`).
3. Applies postgres/ollama StatefulSets and waits for rollout.
4. Applies the orchestrator/ui Deployments (image-triggers pick up the freshly built images automatically) and Routes.
5. Prints the Route URLs.

## Other commands

```
python3 ocp/openshift.py sync-secrets   # re-sync .env / data/accounts / schema.sql without rebuilding
python3 ocp/openshift.py routes         # print route URLs
python3 ocp/openshift.py teardown --yes # delete all NDVM resources in the project
```

## Storage quota

Trial/sandbox projects usually carry small storage quotas. Defaults here are
conservative (`POSTGRES_STORAGE=5Gi`, `OLLAMA_STORAGE=2Gi`); override via
environment variables if your project's quota allows more:
```
POSTGRES_STORAGE=20Gi OLLAMA_STORAGE=5Gi python3 ocp/openshift.py deploy
```
