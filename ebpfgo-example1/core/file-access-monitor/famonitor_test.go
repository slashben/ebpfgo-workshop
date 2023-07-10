package fileaccessmonitor

import (
	"fmt"
	"kubescape-ebpf/core/common"
	"os"
	"os/exec"
	"testing"
)

type TestFileActivityMonitorClient struct {
	listOfEvents []FileActivityEvent
	listOfCids   []string
}

func (client *TestFileActivityMonitorClient) Notify(event FileActivityEvent) {
	cid, _ := common.GetContainerIdForNsMntId(event.NsMntId)
	client.listOfEvents = append(client.listOfEvents, event)
	client.listOfCids = append(client.listOfCids, cid)
}

func TestBpfFileOpen(t *testing.T) {
	// Create client
	client := TestFileActivityMonitorClient{}

	// Create CreateFileActivityMonitor
	am := CreateFileActivityMonitor(&client)

	// Start
	am.Start()

	nonExistentFile := "non-existent-file"
	containerNonExistentFile := "container-non-existent-file"

	// Open a non-existent file
	_, _ = os.Open(nonExistentFile)

	// Open a non-existent file in a container
	exec.Command("docker", "run", "bash:latest", "touch", containerNonExistentFile).Output()

	// Stop
	am.Stop()

	// Check that the file was recorded, loop through the list of files and check if "non-existent-file" is in the list
	found := 0
	for i, event := range client.listOfEvents {
		if event.File == nonExistentFile && event.Pid == os.Getpid() {
			found += 1
		} else if event.File == containerNonExistentFile && client.listOfCids[i] != "" {
			found += 1 // Found in container
		}
	}

	if found != 2 {
		t.Error("File not found")
	}

	fmt.Println("Done")

}

func TestBpfExecve(t *testing.T) {
	// Create client
	client := TestFileActivityMonitorClient{}

	// Create CreateFileActivityMonitor
	am := CreateFileActivityMonitor(&client)

	// Start
	am.Start()

	binLs := "/bin/ls"

	exec.Command(binLs).Output()

	// Stop
	am.Stop()

	// Check that the file was recorded, loop through the list of files and check if "non-existent-file" is in the list
	found := 0
	for _, event := range client.listOfEvents {
		if event.File == binLs {
			found += 1
		}
	}

	if found != 1 {
		t.Error("File not found")
	}

	fmt.Println("Done")

}
