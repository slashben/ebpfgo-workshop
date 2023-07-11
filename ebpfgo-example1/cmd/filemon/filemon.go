package main

import (
	fileaccessmonitor "ebpfgo-example1/core/file-access-monitor"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

type CommandFileActivityMonitorClient struct {
}

func (client *CommandFileActivityMonitorClient) Notify(event fileaccessmonitor.FileActivityEvent) {
	actionString := fmt.Sprintf("Unknown (%d)", event.Operation)
	switch event.Operation {
	case syscall.SYS_EXECVE:
		actionString = "Execve"
	}
	fmt.Println("Cmd:", event.Comm, "Action:", actionString, "File: ", event.File, " PID: ", event.Pid)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Create client
	client := CommandFileActivityMonitorClient{}

	// Create CreateFileActivityMonitor
	am := fileaccessmonitor.CreateFileActivityMonitor(&client)

	// Start
	am.Start()
	defer am.Stop()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
