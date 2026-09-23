# syntax=docker/dockerfile:1
#
# The relay's Redis authority on Fly.io (docs/deploy-fly.md, task row M6-C70):
# TLS only, password required, AOF with appendfsync always, no eviction, data
# on a Fly volume at /data. Build from this directory:
#
#   docker build -t agentuplink-redis deploy/fly/redis
#
# The image holds no certificate, key or password. The entrypoint writes them
# at start-up from Fly secrets (environment variables).

# redis:8.4.0-alpine is the Redis every local harness in this repository runs
# against. The digest is the multi-architecture index.
FROM redis:8.4.0-alpine@sha256:4eec4565e45aa0b3966554c866bc73211e281b0b3d89fe9a33c982e6faca809d
COPY entrypoint.sh /usr/local/bin/agentuplink-redis-entrypoint
RUN chmod 0755 /usr/local/bin/agentuplink-redis-entrypoint
EXPOSE 6379
# Exec form, and the entrypoint `exec`s redis-server (through the image's own
# privilege drop), so Redis receives SIGTERM and shuts down cleanly.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/agentuplink-redis-entrypoint"]
