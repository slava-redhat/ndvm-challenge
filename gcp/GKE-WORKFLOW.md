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
rendered manifests. It also deploys a private, persistent Ollama service and pulls
`nomic-embed-text`; the orchestrator reaches it at `http://ollama:11434`. `OLLAMA_*`,
`INGEST_*`, and local ADC variables are intentionally excluded from the application
Secret so the GKE deployment always uses the embedding model compatible with the
restored local vector database. Each deployment synchronizes both Secrets and restarts
the orchestrator. To copy a later `.env` or ADC credential change:

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

The tier controls the single GKE node and the resource requests/limits rendered into
the Postgres, Ollama, orchestrator, and UI manifests. Ollama is CPU-only and keeps
`nomic-embed-text` on a 5Gi persistent volume.

| Tier | Node | Node estimate/mo* | Use case | Ollama request / limit | Orchestrator request / limit |
|------|------|---:|---|---|---|
| `e2-medium` | 1 shared vCPU, 4GB | ~$25 | Manifest smoke test only; expect slow, contended embedding | 250m / 1 vCPU, 512Mi / 1Gi | 10m / 500m, 256Mi / 1Gi |
| `e2-standard-2` | 2 vCPU, 8GB | ~$49 | Low-volume proof of concept; one interactive request at a time | 500m / 2 vCPU, 1Gi / 2Gi | 100m / 500m, 256Mi / 1Gi |
| `e2-standard-4` | 4 vCPU, 16GB | ~$97 | **Recommended tier**; responsive Ollama retrieval and headroom for GKE system pods | 1 vCPU / 4 vCPU, 1Gi / 2Gi | 250m / 1 vCPU, 256Mi / 2Gi |
| `e2-standard-8` | 8 vCPU, 32GB | ~$194 | Concurrent interactive users or sustained retrieval load | 2 vCPU / 6 vCPU, 2Gi / 4Gi | 500m / 2 vCPU, 512Mi / 2Gi |

\*Node estimates are planning figures only. They exclude persistent disks, the
ingress load balancer, Artifact Registry storage, Cloud Build, network egress, taxes,
and Vertex AI model calls. Use the [Google Cloud Pricing Calculator](https://cloud.google.com/products/calculator)
for the selected region and current price.

### Selecting a tier

Use `e2-standard-4` for a normal interactive RAG deployment:

```bash
export GKE_MACHINE_TYPE=e2-standard-4
python3 gcp/gke.py provision
python3 gcp/gke.py deploy
```

It provides enough headroom for Postgres, the Ollama embedding service, the API, UI,
ingress, and GKE system workloads. Use `e2-standard-8` when measured CPU saturation
or concurrent interactive requests make Ollama retrieval the bottleneck.

For a short functional smoke test, use `e2-standard-2`, then upgrade before
demonstrating concurrent requests or evaluating RAG latency. Tear the environment
down when not actively testing:

```bash
python3 gcp/gke.py teardown --yes
```

### Why E2, and when to benchmark C4D

E2 is the default because this is a balanced, single-node stack: it is broadly
available, cost-effective, and hybrid RAG retrieval is already sub-second. Vertex
model calls, not vector retrieval, dominate end-to-end advice latency. Moving to a
faster CPU family will not materially reduce those remote model calls.

Google positions C4D for CPU-based inference and reports stronger per-vCPU
performance than earlier compute-optimized generations. Benchmark
`c4d-standard-4` or `c4d-standard-8` only if Ollama becomes the measured bottleneck:
machine availability and price vary by zone, and this deployment has not been
validated on that family. Verify availability before changing the node pool:

```bash
gcloud compute machine-types describe c4d-standard-4 \
  --zone="${GCP_ZONE:-us-central1-a}"
```

Do not use Spot nodes for this single-node deployment: Postgres and Ollama are
stateful, so eviction makes the advice service unavailable until recovery. Autopilot
does not remove the need to size the persistent workloads and is not a clear cost or
performance improvement for this fixed four-service stack. Redis, Umami, and the
local-only ingestion workflow are intentionally absent from GKE.
