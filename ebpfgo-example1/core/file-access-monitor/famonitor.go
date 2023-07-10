package fileaccessmonitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf famonitor-ebpf.c -- -I../../includes

type FileOperation int

const (
	Execve FileOperation = syscall.SYS_EXECVE
)

type FileActivityEvent struct {
	Timestamp uint64
	NsMntId   uint64
	Pid       int
	Cgroup    uint64
	Dirfd     int
	File      string
	Comm      string
	Operation FileOperation
}

type FileActivityMonitorClient interface {
	Notify(event FileActivityEvent)
}

type FileActivityMonitor struct {
	objs            bpfObjects
	tracePointLinks []*link.Link
	ringBuf         *ringbuf.Reader
	readLoopOn      bool
	client          FileActivityMonitorClient
}

func CreateFileActivityMonitor(client FileActivityMonitorClient) *FileActivityMonitor {
	return &FileActivityMonitor{client: client}
}

func (fam *FileActivityMonitor) Start() {
	var err error
	// Load related BPF programs and maps into the kernel.
	fam.objs = bpfObjects{}
	if err := loadBpfObjects(&fam.objs, nil); err != nil {
		log.Fatalf("File activity monitor: loading objects: %v", err)
	}

	// Table of tracepoints to monitor.

	// Open tracepoints for the syscalls we want to monitor. Loop over fam.objs.bpfPrograms
	// and attach the tracepoint for each program.
	v := reflect.ValueOf(fam.objs.bpfPrograms)
	t := reflect.TypeOf(fam.objs.bpfPrograms)
	values := make([]interface{}, v.NumField())
	names := make([]string, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		values[i] = v.Field(i).Interface()
		names[i] = t.Field(i).Tag.Get("ebpf")
	}
	for n, prog := range values {
		ebpfProg := prog.(*ebpf.Program)
		tp, err := link.Tracepoint("syscalls", names[n], ebpfProg, nil)
		if err != nil {
			log.Fatalf("File activity monitor: opening tracepoint: %s", err)
		}
		fam.tracePointLinks = append(fam.tracePointLinks, &tp)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	fam.ringBuf, err = ringbuf.NewReader(fam.objs.Events)
	if err != nil {
		log.Fatalf("File activity monitor: opening ringbuf reader: %s", err)
	}

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := fam.ringBuf.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	go func() {
		var event bpfEvent
		for {
			fam.readLoopOn = true
			record, err := fam.ringBuf.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					fam.readLoopOn = false
					return
				}
				continue
			}
			// fmt.Printf("Got event: event record length %d\n", len(record.RawSample))
			// Parse the ringbuf event entry into a bpfEvent structure.
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err == nil {
				e := FileActivityEvent{
					NsMntId:   uint64(event.MntnsId),
					Pid:       int(event.Pid),
					Timestamp: uint64(event.Timestamp),
					File:      unix.ByteSliceToString(event.Path[:]),
					Dirfd:     int(event.Dirfd),
					Comm:      unix.ByteSliceToString(event.Comm[:]),
					Operation: FileOperation(event.SyscallNr),
				}
				fam.client.Notify(e)
				continue
			} else {
				fmt.Println("Error parsing event", err)
			}

		}
	}()
}

func (fam *FileActivityMonitor) Stop() {
	for _, link := range fam.tracePointLinks {
		(*link).Close()
	}
	fam.objs.Close()
}
