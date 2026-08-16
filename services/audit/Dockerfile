ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}
WORKDIR /app
COPY services/audit/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"
COPY services/audit/ /app/
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser
EXPOSE 8011
CMD ["python", "run_uvicorn_tls.py", "main:app", "8011"]
