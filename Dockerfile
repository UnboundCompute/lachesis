# Lachesis MCP server — stdio transport.
#
# Zero-config: start with no graph path and the `build_graph` tool provisions
# graphs on demand from a source directory. Python analysis needs nothing
# further; TypeScript needs Node and C needs clang, both installed here so the
# container can analyze all three supported languages out of the box.
FROM python:3.12-slim

# clang for the C frontend; Node 20 (the supported floor) for the TypeScript
# frontend. curl/gnupg are only needed to add the NodeSource repository.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg clang \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# The published distribution carries the vendored TypeScript compiler, so no
# npm install is needed at analysis time.
RUN pip install --no-cache-dir lachesis-cpg

# A writable home for the content-addressed graph cache.
ENV HOME=/data
RUN mkdir -p /data && chmod 777 /data
WORKDIR /data

# A tiny seed source so the server can build a graph and enter the serve loop in
# an otherwise empty working directory. Real projects are attached at runtime
# with the build_graph tool, which repoints the server to any source tree.
COPY packaging/docker-seed /opt/lachesis-seed

# stdio MCP server. Point it at the seed so it starts immediately; build_graph
# switches to the caller's source on demand.
ENTRYPOINT ["lachesis-mcp", "/opt/lachesis-seed"]
