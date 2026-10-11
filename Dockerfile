FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y clang llvm libbpf-dev bpftool curl git python3
WORKDIR /workspace
