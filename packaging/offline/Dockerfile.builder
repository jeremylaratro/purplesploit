# Builder image for the PurpleSploit offline bundle.
#
# Pinned to kali-rolling so that the resolved wheel tags (cp313 / manylinux) and
# the glibc the PyInstaller binary links against match the target box exactly.
# Building on the Fedora host instead would produce a binary linked against a
# different glibc and wheels resolved for a different interpreter.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        binutils \
        patchelf \
        zlib1g-dev \
        ca-certificates \
        file \
    && rm -rf /var/lib/apt/lists/*

# Isolated venv — Kali's system python is PEP 668 externally-managed.
RUN python3 -m venv /opt/buildenv \
    && /opt/buildenv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/buildenv/bin/pip install pyinstaller==6.19.0

# The build runs as the invoking host uid (so bundle files aren't root-owned),
# which still needs to pip-install into this venv.
RUN chmod -R a+rwX /opt/buildenv

ENV PATH="/opt/buildenv/bin:${PATH}" \
    HOME=/tmp
WORKDIR /work
