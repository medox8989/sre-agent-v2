# SRE Agent v4 — self-contained web UI, no Prometheus/Grafana required.
# Push this to your OCIR registry so nodes never hit Docker Hub rate limits.
#
# ── Build & push ──────────────────────────────────────────────────────────────
#
#   # 1. Login to OCIR (run once per session)
#   #    Username format:  <tenancy-namespace>/<your-oci-username>
#   #    e.g.              ax39qm2olrf8/oracleidentitycloudservice/you@example.com
#   docker login jed.ocir.io
#
#   # 2. Build + push (use deploy.sh build, or manually):
#   docker build -t jed.ocir.io/ax39qm2olrf8/jamiat-images:sre-agent-v5 .
#   docker push  jed.ocir.io/ax39qm2olrf8/jamiat-images:sre-agent-v5
#
#   # 3. Deploy:
#   ./deploy.sh          # jamiat (default)
#   CLUSTER=proptech-lite ./deploy.sh
#   CLUSTER=awqaf         ./deploy.sh
#
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-alpine

# Install Python dependencies (prometheus_client removed in v4)
RUN pip install \
      kubernetes==29.0.0 \
      requests==2.31.0 \
      --no-cache-dir

# Create non-root user
RUN adduser -D -u 1000 sreagent
WORKDIR /app

# Bake the agent source into the image
COPY agent.py .

USER sreagent

CMD ["python", "agent.py"]
