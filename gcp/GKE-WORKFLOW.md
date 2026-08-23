# NDVM GKE Workflow

This deployment prepares the GKE equivalents of the persistent pgvector database,
FastAPI orchestrator, and Streamlit UI. The vector corpus is deliberately cloned from
the local database rather than re-ingested in GKE. All provisioning and deploy logic
is in `gcp/gke.py`; no shell wrapper is required.

## Prerequisites

- `gcloud`, `kubectl`, and the GKE auth plugin.
- A GCP project in which you can create GKE, Artifact Registry, and Cloud Build
  resources.
- Vertex access for the selected `NDVM_LLM_MODEL` and `NDVM_FAST_LLM_MODEL`.

### Isolated GCP authentication environment

Create and use a dedicated Conda environment so GCP authentication and deployment
commands do not modify the current Python environment. The Python deployment tools
use only the standard library, so **do not install any Python packages** in it.

```bash
conda create -n gcp-auth python=3.12 -y
conda activate gcp-auth
python --version
```

Install `gcloud`, `kubectl`, and the GKE auth plugin through the operating-system
package manager or Google Cloud SDK; they are command-line tools, not Conda packages.

Conda does not isolate `gcloud` credentials by itself. Configure this environment to
use its own Google Cloud SDK directory, then reactivate it:

```bash
conda env config vars set CLOUDSDK_CONFIG="$HOME/.config/gcloud-gcp-auth"
conda deactivate
conda activate gcp-auth
echo "$CLOUDSDK_CONFIG"
```

`gcloud auth login` stores its login under `~/.config/gcloud-gcp-auth`; it does not
reuse or overwrite the default `~/.config/gcloud` login. With `gcp-auth` active,
install the GKE kubectl auth plugin if it is not already available, then authenticate:

```bash
gcloud components install kubectl gke-gcloud-auth-plugin
gcloud auth login
```

`gcloud auth application-default login` is required before deployment. It writes the
ADC file under `~/.config/gcloud-gcp-auth`, which must be copied to the untracked file
used by the deployment:

```bash
gcloud auth application-default login
cp "$CLOUDSDK_CONFIG/application_default_credentials.json" \
  .application_default_credentials.json
```

The active Conda environment and its `CLOUDSDK_CONFIG` setting last only for the
current shell. Exit it after GCP work with `conda deactivate`.

## Configuration

The Python command reads configuration from environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `GCP_PROJECT_ID` | current gcloud project | GCP project |
| `GCP_REGION` | `us-central1` | Artifact Registry region |
| `GCP_ZONE` | `${GCP_REGION}-a` | Single-node GKE zone |
| `GKE_CLUSTER_NAME` | `ndvm` | GKE cluster name |
| `ARTIFACT_REPOSITORY` | `ndvm` | Docker repository name |
| `K8S_NAMESPACE` | `ndvm` | Kubernetes namespace |
| `GKE_MACHINE_TYPE` | `e2-standard-2` | Resource tier |

Create `.env` from `.env.example`, set the Vertex project/model values, a non-default
Postgres password, and the desired embedding model. Keep
`.application_default_credentials.json` untracked; deployment stores it only as the
`ndvm-google-credentials` Kubernetes Secret.

The synthetic TAM estates in `data/accounts/*.json` are copied during deployment into
the `ndvm-account-data` ConfigMap and mounted read-only at `/app/data/accounts`. After
editing those files, run `python3 gcp/gke.py sync-secrets` to update the ConfigMap and
restart the orchestrator.

```bash
cp .env.example .env
export GCP_PROJECT_ID="your-project"
```

## 1. Provision

```bash
python3 gcp/gke.py provision
```

This enables the required APIs, creates the Artifact Registry repository, creates a
single-node GKE cluster, and installs ingress-nginx.

## 2. Deploy

```bash
python3 gcp/gke.py deploy
python3 gcp/gke.py deploy --tag v1.0.0
```

The command builds and pushes the orchestrator and UI images concurrently with Cloud
Build, creates the `ndvm-secrets` Secret from `.env` on its first run, and applies the
rendered manifests. `OLLAMA_*`, `INGEST_*`, and local ADC variables are intentionally
excluded from the application Secret. Each deployment synchronizes both Secrets and
restarts the orchestrator. To copy a later `.env` or ADC credential change:

```bash
python3 gcp/gke.py sync-secrets
```

## 3. Clone the local vector database

After local ingestion completes, keep the local `db` container running and create a
compressed backup:

```bash
make up
make vector-db-backup
```

This creates `gcp/backups/ndvm-vector.sql.gz`. It includes every NDVM database table:
all `doc_chunk` rows and their pgvector embeddings, mitigation/CVE data, product
states, and the ingestion ledger.

Provision and deploy first. Then configure `kubectl` for the cluster and wait until
the target Postgres pod is ready:

```bash
gcloud container clusters get-credentials "${GKE_CLUSTER_NAME:-ndvm}" \
  --zone="${GCP_ZONE:-us-central1-a}" \
  --project="${GCP_PROJECT_ID}"
kubectl -n "${K8S_NAMESPACE:-ndvm}" rollout status statefulset/postgres --timeout=180s
make vector-db-restore
```

The restore scales the orchestrator to zero, replaces the data in Postgres with the
backup, then restores the original replica count. Use the same custom path for both
commands when retaining snapshots:

```bash
make vector-db-backup VECTOR_DB_BACKUP=/secure/backups/ndvm-2026-08-22.sql.gz
make vector-db-restore VECTOR_DB_BACKUP=/secure/backups/ndvm-2026-08-22.sql.gz
```

## 4. Operate

```bash
kubectl -n ndvm get pods,svc,ingress
kubectl -n ndvm logs deployment/orchestrator --tail=100
```

### Access the ingress

The ingress controller creates an external load balancer. Its address can take several
minutes after provisioning. Wait for it, then print the URLs:

```bash
until INGRESS_ADDRESS="$(kubectl -n ingress-nginx get svc ingress-nginx-controller \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}')" \
  && [ -n "$INGRESS_ADDRESS" ]; do
  echo "Waiting for ingress address..."
  sleep 10
done

echo "UI:  http://${INGRESS_ADDRESS}/"
echo "API: http://${INGRESS_ADDRESS}/health"
```

`python3 gcp/gke.py deploy` prints the NDVM ingress URL once the rollout completes.
To retrieve it later, or wait for a newly provisioned address:

```bash
python3 gcp/gke.py ingress --wait
```

Open the printed **UI** URL in a browser. Confirm the API separately:

```bash
curl -fsS "http://${INGRESS_ADDRESS}/health"
```

The API also exposes `/accounts`, `/triage`, `/advise`, and `/advise_stream` at that
same address. To inspect ingress routing or troubleshoot an unavailable address:

```bash
kubectl -n ndvm get ingress ndvm
kubectl -n ingress-nginx get svc ingress-nginx-controller
kubectl -n ingress-nginx get pods
```

## 5. Upgrade Tier

GKE machine types cannot be changed in place. Create a replacement node pool, drain
the old node, then redeploy with the matching resource tier:

```bash
gcloud container node-pools create ndvm-upgrade \
  --cluster=ndvm --zone="${GCP_ZONE:-us-central1-a}" \
  --machine-type=e2-standard-4 --num-nodes=1 --disk-size=30
kubectl get nodes
kubectl cordon <old-node>
kubectl drain <old-node> --ignore-daemonsets --delete-emptydir-data
gcloud container node-pools delete default-pool \
  --cluster=ndvm --zone="${GCP_ZONE:-us-central1-a}"
GKE_MACHINE_TYPE=e2-standard-4 python3 gcp/gke.py deploy
```

## 6. Teardown

This irreversibly removes the cluster and Artifact Registry images:

```bash
python3 gcp/gke.py teardown --yes
```

## Resource Tiers

| Tier | vCPU | RAM | ~Cost/mo | Postgres | Orchestrator | UI |
|------|------|-----|----------|----------|--------------|----|
| `e2-medium` | 1 (shared) | 4GB | $25 | 25m | 10m | 10m |
| `e2-standard-2` | 2 | 8GB | $49 | 100m | 100m | 100m |
| `e2-standard-4` | 4 | 16GB | $97 | 250m | 250m | 250m |

The CPU values above are pod requests. Each manifest also assigns a bounded higher
CPU and memory limit, so a service can burst without reserving the whole node. Redis,
Umami, and the local-only ingestion workflow are intentionally absent from GKE.
