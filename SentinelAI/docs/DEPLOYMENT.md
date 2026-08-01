# SentinelAI — Deployment Guide

## 1. Local Development

### Prerequisites
| Tool | Min Version | Install |
|---|---|---|
| Python | 3.11+ | https://www.python.org/downloads/ |
| Git | 2.40+ | https://git-scm.com |

### Quick Start
```bash
git clone https://github.com/faris7assan/SentinelAI
cd SentinelAI
make setup          # Creates .env and local data folders
python scripts/start_local_dev.py
```

### Service URLs
| Service | URL |
|---|---|
| Local backend | http://127.0.0.1:8000 |
| Desktop app | launches automatically in local dev mode |
| Frontend | http://localhost:3000 if run separately |

### Default Credentials
```
Dashboard: admin / SentinelAI@2024  ← CHANGE IMMEDIATELY
Grafana:   admin / (from POSTGRES_PASSWORD in .env)
RabbitMQ:  sentinelai / (from REDIS_PASSWORD in .env)
```

### Install LLM
```bash
make ollama-pull    # Pulls llama3.2 (~2GB)
```

### Initialize OpenSearch
```bash
make opensearch-setup
```

### Install endpoint agent
```bash
sudo bash scripts/install_agent.sh \
  --server http://YOUR_SERVER:8000 \
  --token YOUR_JWT_TOKEN
```

---

## 2. Production Kubernetes (AWS EKS)

### Prerequisites
- AWS account with admin access
- `kubectl` ≥ 1.29
- `terraform` ≥ 1.7
- `helm` ≥ 3.14

### Step 1 — Provision Infrastructure
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Fill in db_password, redis_password, domain, etc.
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```
This provisions: EKS cluster, RDS PostgreSQL, ElastiCache Redis, MSK Kafka, OpenSearch, KMS keys.

### Step 2 — Configure kubectl
```bash
aws eks update-kubeconfig \
  --region us-east-1 \
  --name sentinelai-eks
kubectl get nodes   # Verify cluster is reachable
```

### Step 3 — Create Kubernetes Secrets
```bash
kubectl create namespace sentinelai

kubectl create secret generic sentinelai-secrets \
  --namespace sentinelai \
  --from-literal=JWT_SECRET_KEY="$(openssl rand -hex 64)" \
  --from-literal=POSTGRES_PASSWORD="YOUR_DB_PASSWORD" \
  --from-literal=REDIS_PASSWORD="YOUR_REDIS_PASSWORD" \
  --from-literal=OPENSEARCH_PASSWORD="YOUR_OS_PASSWORD" \
  --from-literal=VIRUSTOTAL_API_KEY="YOUR_VT_KEY" \
  --from-literal=ABUSEIPDB_API_KEY="YOUR_ABUSE_KEY"
```

### Step 4 — Deploy Platform
```bash
# Update image references in kubernetes/sentinelai-full.yaml
sed -i 's|sentinelai/|ghcr.io/faris7assan/sentinelai/|g' kubernetes/sentinelai-full.yaml

kubectl apply -f kubernetes/sentinelai-full.yaml
kubectl rollout status deployment --all -n sentinelai --timeout=300s
```

### Step 5 — Configure DNS
Point your domain to the ALB/NLB created by the Kubernetes Ingress:
```bash
kubectl get ingress -n sentinelai
# Copy the ADDRESS and create DNS A record: sentinelai.yourdomain.com → ADDRESS
```

### Step 6 — Install Cert-Manager (TLS)
```bash
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true

# Apply Let's Encrypt ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
```

### Monitoring
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set grafana.adminPassword=YOUR_GRAFANA_PASSWORD
```

---

## 3. CI/CD Pipeline (GitHub Actions)

The pipeline in `.github/workflows/ci-cd.yml` runs automatically on push to `main`:

1. **Security Scan** — Bandit (Python), Trivy (containers), Gitleaks (secrets)
2. **Test Backend** — pytest with Redis/PostgreSQL test services
3. **Test Frontend** — Next.js build check
4. **Build & Push** — All 9 backend + frontend images → GHCR
5. **Deploy** — `kubectl rollout restart` all deployments

### Required GitHub Secrets
```
KUBECONFIG          Base64-encoded kubeconfig for production cluster
SLACK_WEBHOOK_URL   For deployment notifications
```

---

## 4. Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ | 64-char random hex — `openssl rand -hex 64` |
| `POSTGRES_PASSWORD` | ✅ | Strong password for PostgreSQL |
| `REDIS_PASSWORD` | ✅ | Password for Redis |
| `OPENSEARCH_PASSWORD` | ✅ | OpenSearch admin password |
| `VIRUSTOTAL_API_KEY` | ⚡ | Free tier: 4 req/min |
| `ABUSEIPDB_API_KEY` | ⚡ | Free tier: 1k/day |
| `ALIENVAULT_OTX_KEY` | ⚡ | Free at otx.alienvault.com |
| `SHODAN_API_KEY` | ⚡ | Paid, ~$59/mo for full access |
| `MISP_URL` + `MISP_API_KEY` | ⚡ | Self-hosted MISP instance |
| `OPENCTI_URL` + `OPENCTI_API_KEY` | ⚡ | Self-hosted OpenCTI |
| `SLACK_WEBHOOK_URL` | ⚡ | For SOAR Slack notifications |
| `SMTP_HOST/USER/PASSWORD` | ⚡ | For email alerts |
| `GOOGLE_CLIENT_ID/SECRET` | ⚡ | OAuth2 Google SSO |
| `GITHUB_CLIENT_ID/SECRET` | ⚡ | OAuth2 GitHub SSO |
| `AZURE_TENANT_ID` + `AZURE_CLIENT_ID/SECRET` | ⚡ | OAuth2 Microsoft SSO |
| `CUCKOO_API_URL` | ⚡ | Cuckoo sandbox integration |
| `OLLAMA_MODEL` | — | Default: `llama3.2` |

✅ = Required  ⚡ = Recommended for full functionality

---

## 5. Agent Deployment

### Linux (auto-install)
```bash
sudo bash scripts/install_agent.sh \
  --server https://sentinelai.yourdomain.com \
  --token YOUR_ANALYST_JWT_TOKEN \
  --id your-hostname
```
Installs as systemd service: `sentinelai-agent.service`

### Windows (manual)
```powershell
# Install Python 3.11
pip install aiohttp loguru

# Run agent
python C:\sentinelai\windows_agent.py
```
Set env vars: `SENTINELAI_API`, `SENTINELAI_TOKEN`, `AGENT_ID`

### Osquery (Windows)
```powershell
python scripts/windows_agent.py
```
Set env vars: `SENTINELAI_API`, `SENTINELAI_TOKEN`, `AGENT_ID`

---

## 6. Scaling Guide

### Detection Engine (Kafka bottleneck)
```bash
# Scale detection engine replicas
kubectl scale deployment detection-engine -n sentinelai --replicas=5
# Add Kafka partitions
kubectl exec -n sentinelai kafka-0 -- kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --alter --topic sentinelai.logs --partitions 10
```

### AI Service (CPU-heavy)
```bash
kubectl scale deployment ai-service -n sentinelai --replicas=3
# Or use GPU nodes:
kubectl patch deployment ai-service -n sentinelai \
  --patch '{"spec":{"template":{"spec":{"nodeSelector":{"role":"gpu"}}}}}'
```

### Log Ingestion (high volume)
```bash
# Scale log service + increase Kafka retention
kubectl scale deployment log-service -n sentinelai --replicas=4
```

---

## 7. Performance Targets

| Metric | Target | How to validate |
|---|---|---|
| Log ingestion | 50,000 events/sec | `make simulate` with bulk logs |
| Alert detection latency | < 500ms | Check Kafka consumer lag |
| AI enrichment | < 2s per alert | GET /ai/stats response times |
| SOAR response | < 5s | GET /soar/executions total_time_ms |
| Dashboard WS latency | < 100ms | Browser DevTools → Network → WS |
| API response (p99) | < 200ms | Grafana → API Response Time panel |
