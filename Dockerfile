FROM python:3.8-slim as base
FROM base as builder
COPY requirements.txt /
RUN pip install --user -r /requirements.txt
FROM base
ENV PATH=/root/.local/bin:$PATH
COPY --from=builder /root/.local /root/.local
WORKDIR /app
COPY scanner.py .
COPY trivy .
CMD ["/app/scanner.py"]