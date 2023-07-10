FROM ubuntu:latest

# Install Go and eBPF environment
RUN apt-get update && apt-get install -y golang clang llvm libelf-dev libpcap-dev build-essential git
RUN mkdir /work
ENV GOPATH=/work
WORKDIR /work