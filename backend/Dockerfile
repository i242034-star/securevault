# =============================================================================
# SecureVault Backend Production Dockerfile
# Ubuntu 24.04 + Python 3.12 + Stanford PBC + GMP + Charm-Crypto BSW07 + Gunicorn
# =============================================================================

FROM ubuntu:24.04

# Avoid interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system build dependencies, GMP, OpenSSL, and Python 3.12 dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    flex \
    bison \
    libgmp-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# 1. Download, verify, build, and install Stanford PBC Library (0.5.14)
#    TLS is verified and the tarball is pinned by SHA-256 (supply-chain check).
ARG PBC_SHA256=772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2
RUN wget -q https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && echo "${PBC_SHA256}  pbc-0.5.14.tar.gz" | sha256sum -c - \
    && tar -xzf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure --prefix=/usr \
    && make -j$(nproc) \
    && make install \
    && ldconfig \
    && cd .. \
    && rm -rf pbc-0.5.14*

# 2. Fetch, build, and install Charm-Crypto Framework pinned to an exact commit.
#    b2db00b (2026-09-10) is the revision the crypto + attack-lab tests pass on.
#    The older v0.63 release tag is NOT compatible with this code base.
ARG CHARM_COMMIT=b2db00be7adf681c6bc35d35be3682ba047b3577
RUN mkdir charm && cd charm \
    && git init -q \
    && git remote add origin https://github.com/JHUISI/charm.git \
    && git fetch -q --depth 1 origin ${CHARM_COMMIT} \
    && git checkout -q FETCH_HEAD \
    && ./configure.sh --prefix=/usr \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf charm

WORKDIR /app

# 3. Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# 4. Copy backend source code and baseline storage
COPY . .

# Ensure storage directories exist and belong to the unprivileged runtime user.
# UID 1000 is the stock "ubuntu" user in ubuntu:24.04. Only storage/ is writable;
# the code is not.
RUN mkdir -p storage/keys storage/encrypted \
    && chown -R 1000:1000 storage

# Drop root: the API never needs it at runtime
USER 1000

# Default port; hosts such as Railway inject their own $PORT (8080), which the CMD below honours
ENV PORT=10000
EXPOSE 10000

# Healthcheck to verify service availability
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import os, urllib.request; urllib.request.urlopen('http://localhost:' + str(os.environ.get('PORT', 10000)) + '/api/health')" || exit 1

# Start production server with Gunicorn.
# ONE worker process (with threads) on purpose: the Trusted Authority's master
# key is created on first boot, the login rate limiter is in-process, and the
# store is SQLite. Several worker processes would race to create different
# master keys and would each keep a separate lockout counter.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 120 wsgi:app"]
