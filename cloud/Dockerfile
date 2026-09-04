# SDA Pathfinder -- cloud image.
#
# Pinned to Python 3.12 on linux/amd64: the bundled RADKit wheels are
# cp312-none-manylinux1_x86_64, so a 3.11 or 3.13 base cannot install them
# even though run.sh advertises 3.10-3.13 for the standalone app.

FROM --platform=linux/amd64 python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Same resolution order as run.sh: bundled wheels first, then Cisco's index
# (the PyPI package is a stub that errors out), then PyPI for transitive deps.
COPY radkit-wheels/ ./radkit-wheels/
RUN pip install \
      --find-links ./radkit-wheels \
      --extra-index-url https://radkit.cisco.com/pip \
      cisco-radkit-client==1.9.9 cisco-radkit-common==1.9.9 \
      cisco-radkit-genie==1.9.9 cisco-radkit-service==1.9.9


FROM --platform=linux/amd64 python:3.12-slim

# HOME must be writable: pyATS/Genie writes there, and OpenShift runs the
# container as a random high UID with no passwd entry, so the default home
# does not exist. An unwritable HOME breaks Genie parsing at runtime.
ENV PATH="/opt/venv/bin:$PATH" \
    HOME=/tmp \
    DATA_DIR=/tmp/sda-pathfinder \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy the application explicitly rather than `COPY . /app`. A blanket copy
# depends on .dockerignore listing every stray directory by name, and a working
# tree accumulates scratch data -- a 6.8 GB directory of case logs once made
# this image ~10x larger. An allowlist cannot leak what it does not name.
COPY checks/ /app/checks/
COPY cloud/ /app/cloud/
COPY catalystcenterapi/ /app/catalystcenterapi/
COPY routingmodules/ /app/routingmodules/
COPY securitymodules/ /app/securitymodules/
COPY switchingmodules/ /app/switchingmodules/
COPY wirelessmodules/ /app/wirelessmodules/
COPY traffic_flows/ /app/traffic_flows/
COPY static/ /app/static/
COPY check_registry.py device_profiler.py forwardinglogic.py hostonboarding.py \
     ipverifications.py radkit_cli.py scenario_runner.py server.py \
     VERSION /app/

# Cache-buster for static assets. Without it _read_version has no .git to read
# and falls back to VERSION, so browsers keep stale app.js across deploys.
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

# OpenShift assigns a random UID with GID 0 -- group-writable, not USER 1000.
RUN chgrp -R 0 /app && chmod -R g=u /app
USER 1001

EXPOSE 8000

# Single worker on purpose: multiple workers fork separate `sessions` dicts and
# break the in-process session model. Concurrency comes from replicas.
CMD ["python", "-m", "uvicorn", "cloud.server:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--timeout-graceful-shutdown", "90"]
