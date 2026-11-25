FROM python:3.12-slim-bookworm
WORKDIR /app

# Disable stdout/stderr buffering so ``docker logs`` shows server output
# in real time. Without this, prints/log-stream messages can sit in the
# buffer indefinitely and the container looks silent.
# phxd runs unprivileged and can't write to /app, so don't try to write
# bytecode caches there (they are precompiled below).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# The unprivileged user phxd runs as (see docker/run-phxd.sh).
RUN groupadd --system --gid 10001 phxd \
 && useradd --system --uid 10001 --gid phxd --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin phxd

COPY requirements.txt /app

RUN pip install --no-cache-dir -r requirements.txt

# The application stays owned by root and read-only to phxd, so even a
# compromised phxd process can't change its own code.
COPY config.py /app/config.py
COPY phxd /app/phxd
COPY server /app/server
COPY shared /app/shared
COPY support /app/support
COPY configure_phxd.py /app/configure_phxd.py
COPY docker/run-phxd.sh /usr/local/bin/run-phxd

# 5500 = control connection (HLServer); 5501 = file transfer port
# (HLFileServer binds to SERVER_PORT + 1). Both must be published with
# `-p` at `docker run` time, otherwise downloads fail with
# "Failed to connect for file transfer: Connection refused".
EXPOSE 5500/tcp
EXPOSE 5501/tcp
EXPOSE 5600/tcp
EXPOSE 5601/tcp
EXPOSE 6697/tcp

RUN python configure_phxd.py \
 && python -m compileall -q /app \
 && chmod 0755 /usr/local/bin/run-phxd

# Prepares the data directories and drops root before starting phxd.
ENTRYPOINT [ "/usr/local/bin/run-phxd" ]
CMD [ "python", "phxd" ]
