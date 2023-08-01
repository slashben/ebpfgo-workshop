# eBPF workshop environment

## Setup

Everything you need in this workshop is in the `Containerfile` in this directory. To build the container and enter it with all the setting you need, run the following command and you will have a shell with all the things you need.

```bash
./enter-dev-container.sh
```

## Compiling the example project

There is an example eBPF go project in the `ebpfgo-example1` directory. To build it, run the following command:
```bash
go mod tidy && go build -buildvcs=false cmd/filemon/filemon.go
```

To try it, run the `./filemon` executable and open other processes to see that it detects their events.
