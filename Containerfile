# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# ABHED-v2 in one image: liboqs, libabhed, tools, patched NSD, patched Unbound, Go tools.
#   podman build -t abhed:2.1 .
#   podman run --rm -it abhed:2.1 bash deploy/test.sh
FROM docker.io/library/ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential cmake ninja-build autoconf automake libtool flex bison \
      pkg-config libssl-dev libevent-dev libexpat1-dev libldns-dev golang-go \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src/abhed
COPY . .
RUN chmod +x deploy/*.sh && bash deploy/build.sh --prefix /opt/abhed

FROM docker.io/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3t64 libevent-2.1-7t64 libexpat1 libldns3t64 dnsutils procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/abhed /opt/abhed
COPY --from=build /src/abhed/deploy /opt/abhed/deploy
ENV PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH
WORKDIR /opt/abhed
CMD ["bash", "deploy/test.sh"]
