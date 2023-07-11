#!/bin/bash
docker build -t ebpf-env -f Containerfile .
# Check if the build was successful
if [ $? -eq 0 ]; then
    # Check if running on Mac or Linux
    sys_mount_arg="-v /sys:/sys"
    if [ "$(uname)" == "Darwin" ]; then
        # Mac
        sys_mount_arg=""
    fi
    docker run -v $PWD:/work -w /work $sys_mount_arg -it --rm --privileged --net=host --pid=host --security-opt seccomp=unconfined ebpf-env bash
else
    echo "Build failed"
fi