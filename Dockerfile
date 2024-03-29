FROM python:3.11-slim as base

# Run tests
FROM base as tester
COPY requirements-development.txt /
RUN pip install -r /requirements-development.txt
RUN apt-get update && apt-get install -y make && apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/
WORKDIR /app
COPY tests/ /app/tests
COPY Makefile .
COPY .coveragerc .
COPY scanner.py .
COPY version.py .
COPY tests.py .
COPY scripts/ /app/scripts
RUN make test

# If tests OK, download all deps and install download trivy
FROM base as builder
COPY requirements.txt /
COPY scripts/download_trivy.sh /
ARG TRIVY_VERSION=0.47.0
RUN apt-get update && apt-get install -y wget && apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/
RUN pip install --user -r /requirements.txt && \
    chmod +x /download_trivy.sh && /download_trivy.sh

# Clean image
FROM base
ENV PATH=/root/.local/bin:$PATH
COPY --from=builder /root/.local /root/.local
RUN apt-get update && apt-get install -y rpm && apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/ && mkdir -p /data/trivycache
WORKDIR /app
COPY scanner.py .
COPY version.py .
COPY --from=builder /tmp/trivy .
ENV TRIVY_CACHE_DIR /data/trivycache
CMD ["/usr/local/bin/python", "/app/scanner.py"]