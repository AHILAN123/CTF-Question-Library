# CTF Q1 -- Linux x86-64 build/runtime for the whole pipeline.
# Anti-debug in part2 uses x86 rdtsc/INT3 + Linux ptrace + /proc, so the image
# is pinned to linux/amd64 (runs under emulation on Apple Silicon; native x86-64
# is recommended for the timing check to behave).
FROM --platform=linux/amd64 ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential python3 libssl-dev binutils zip gdb \
        python3-pyelftools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /ctf
COPY . /ctf
# Build everything (compiles part2/part3, generates circuits, runs self-tests).
RUN chmod +x build.sh && ./build.sh
EXPOSE 31337
ENV CTF_SECRET=/ctf/build/circuit_secret.json CTF_HOST=0.0.0.0 CTF_PORT=31337
CMD ["python3", "nc_server.py"]
