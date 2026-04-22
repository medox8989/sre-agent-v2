# SRE Agent — builds a self-contained image with all deps baked in.
# Push this to your OCIR registry so nodes never hit Docker Hub rate limits.
#
# ── Build & push ──────────────────────────────────────────────────────────────
#
#   # 1. Login to OCIR (run once per session)
#   #    Username format:  <tenancy-namespace>/<your-oci-username>
#   #    e.g.              ax39qm2olrf8/oracleidentitycloudservice/you@example.com
#   docker login jed.ocir.io
#
#   # 2. Build
#   docker build -t jed.ocir.io/ax39qm2olrf8/jamiat-images:sre-agent-v1 .
#
#   # 3. Push
#   docker push jed.ocir.io/ax39qm2olrf8/jamiat-images:sre-agent-v1
#
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-alpine

# Install Python dependencies
RUN pip install \
      kubernetes==29.0.0 \
      requests==2.31.0 \
      prometheus_client==0.20.0 \
      --no-cache-dir

# Create non-root user
RUN adduser -D -u 1000 sreagent
WORKDIR /app

# Bake the agent source into the image
COPY agent.py .

USER sreagent

CMD ["python", "agent.py"]
