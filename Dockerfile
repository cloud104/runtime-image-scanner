FROM python:3.8-slim as base
FROM base as builder
COPY requirements.txt /
RUN pip install --user -r /requirements.txt
FROM base
ENV PATH=/root/.local/bin:$PATH
COPY --from=builder /root/.local /root/.local
RUN apt-get update && apt-get install -y  rpm && apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/
WORKDIR /app
COPY scanner.py .
COPY trivy .
CMD ["/app/scanner.py"]