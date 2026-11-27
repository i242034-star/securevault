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

# 1. Download, build, and install Stanford PBC Library (0.5.14)
RUN wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar -xzf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure --prefix=/usr \
    && make -j$(nproc) \
    && make install \
    && ldconfig \
    && cd .. \
    && rm -rf pbc-0.5.14*

# 2. Clone, build, and install Charm-Crypto Framework
RUN git clone --depth 1 https://github.com/JHUISI/charm.git \
    && cd charm \
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
# UID 1000 is the stock "ubuntu" user in ubuntu:24.04, and is also the UID that
# Hugging Face Spaces runs containers as. Only storage/ is writable; the code is not.
RUN mkdir -p storage/keys storage/encrypted \
    && chown -R 1000:1000 storage

# Drop root: the API never needs it at runtime
USER 1000

# Port 10000 (Render's default; Hugging Face reads app_port from README.md)
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
