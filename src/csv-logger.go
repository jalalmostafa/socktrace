package main

import (
	"errors"
	"fmt"
	"os"
)

type SocktraceEventLog struct {
	pid  int
	file *os.File
}

func CreateEventLoggerWithHeaders(pid int) (*SocktraceEventLog, error) {
	var err error
	perf := new(SocktraceEventLog)
	perf.pid = pid
	path := fmt.Sprintf("socktrace-%d.csv", pid)

	perf.file, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	_, err = perf.file.WriteString("SocketCookie,ParentCookie,TimestampNS,PID,TGID,Syscall,FileDescriptor\n")
	if err != nil {
		return nil, err
	}

	err = perf.file.Sync()
	if err != nil {
		return nil, err
	}

	return perf, err
}

func (perf *SocktraceEventLog) WriteEvent(event *SocketEvent) error {
	if perf.file == nil {
		return errors.New("invalid file")
	}

	row := fmt.Sprintf("%d,%d,%d,%d,%d,%s,%d\n",
		event.Cookie, event.ParentCookie, event.TimestampNs,
		event.Pid, event.Tgid, socktrace_syscalls[int(event.Operation)],
		event.FileDescriptor)

	_, err := perf.file.WriteString(row)
	if err != nil {
		err = perf.file.Sync()
	}

	return nil
}

func (perf *SocktraceEventLog) Close() error {
	if perf.file == nil {
		return errors.New("invalid file")
	}

	return perf.file.Close()
}
