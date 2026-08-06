package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	MAX_PROCESSES = 256
	MAX_SOCKETS   = 64
	IPC_PATH      = "/tmp/socktrace.sock"
)

var CONTROL_PROGRAMS = []string{"trace_kernel_clone", "trace_fd_install"}

type SocktraceArgs struct {
	help bool
	file bool
}

type SocketEvent struct {
	Cookie         uint64
	ParentCookie   uint64
	TimestampNs    uint64
	Pid            uint32
	Tgid           uint32
	Operation      uint32
	FileDescriptor uint32
}

type SockTracer struct {
	Objs        SocktraceEbpfObjects
	Context     context.Context
	Links       []link.Link
	EventsRing  *RingChannel[SocketEvent]
	ProcessRing *RingChannel[uint32]
}

const (
	SOCKTRACE_SYSCALL_SOCKET uint32 = iota
	SOCKTRACE_SYSCALL_BIND
	SOCKTRACE_SYSCALL_LISTEN
	SOCKTRACE_SYSCALL_CONNECT
	SOCKTRACE_SYSCALL_ACCEPT
	SOCKTRACE_SYSCALL_ACCEPT4
	SOCKTRACE_SYSCALL_RECVFROM
	SOCKTRACE_SYSCALL_RECVMSG
	SOCKTRACE_SYSCALL_RECVMMSG
	SOCKTRACE_SYSCALL_SENDTO
	SOCKTRACE_SYSCALL_SENDMSG
	SOCKTRACE_SYSCALL_SENDMMSG
	SOCKTRACE_SYSCALL_SETSOCKOPT
	SOCKTRACE_SYSCALL_GETSOCKOPT
	SOCKTRACE_SYSCALL_GETPEERNAME
	SOCKTRACE_SYSCALL_GETSOCKNAME
	SOCKTRACE_SYSCALL_SHUTDOWN
	SOCKTRACE_SYSCALL_READ
	SOCKTRACE_SYSCALL_READV
	SOCKTRACE_SYSCALL_WRITE
	SOCKTRACE_SYSCALL_WRITEV
	SOCKTRACE_SYSCALL_CLOSE
	SOCKTRACE_SYSCALL_POLL
	SOCKTRACE_SYSCALL_PPOLL
	SOCKTRACE_SYSCALL_SELECT
	SOCKTRACE_SYSCALL_PSELECT
	SOCKTRACE_SYSCALL_EPOLL_CREATE
	SOCKTRACE_SYSCALL_EPOLL_CREATE1
	SOCKTRACE_SYSCALL_EPOLL_CTL
	SOCKTRACE_SYSCALL_EPOLL_WAIT
	SOCKTRACE_SYSCALL_EPOLL_PWAIT
	SOCKTRACE_SYSCALL_EPOLL_PWAIT2
	SOCKTRACE_SYSCALL_SENDFILE64
	SOCKTRACE_SYSCALL_IOCTL
	SOCKTRACE_SYSCALL_SPLICE
	SOCKTRACE_SYSCALL_TEE
	SOCKTRACE_SYSCALL_DUP
	SOCKTRACE_SYSCALL_DUP2
	SOCKTRACE_SYSCALL_DUP3
	SOCKTRACE_SYSCALL_SOCKETPAIR
	SOCKTRACE_SYSCALL_MAX
)

var socktrace_syscalls = map[uint32]string{
	SOCKTRACE_SYSCALL_SOCKET:        "socket",
	SOCKTRACE_SYSCALL_BIND:          "bind",
	SOCKTRACE_SYSCALL_LISTEN:        "listen",
	SOCKTRACE_SYSCALL_CONNECT:       "connect",
	SOCKTRACE_SYSCALL_ACCEPT:        "accept",
	SOCKTRACE_SYSCALL_ACCEPT4:       "accept4",
	SOCKTRACE_SYSCALL_RECVFROM:      "recvfrom",
	SOCKTRACE_SYSCALL_RECVMSG:       "recvmsg",
	SOCKTRACE_SYSCALL_RECVMMSG:      "recvmmsg",
	SOCKTRACE_SYSCALL_SENDTO:        "sendto",
	SOCKTRACE_SYSCALL_SENDMSG:       "sendmsg",
	SOCKTRACE_SYSCALL_SENDMMSG:      "sendmmsg",
	SOCKTRACE_SYSCALL_SETSOCKOPT:    "setsockopt",
	SOCKTRACE_SYSCALL_GETSOCKOPT:    "getsockopt",
	SOCKTRACE_SYSCALL_GETPEERNAME:   "getpeername",
	SOCKTRACE_SYSCALL_GETSOCKNAME:   "getsockname",
	SOCKTRACE_SYSCALL_SHUTDOWN:      "shutdown",
	SOCKTRACE_SYSCALL_READ:          "read",
	SOCKTRACE_SYSCALL_READV:         "readv",
	SOCKTRACE_SYSCALL_WRITE:         "write",
	SOCKTRACE_SYSCALL_WRITEV:        "writev",
	SOCKTRACE_SYSCALL_CLOSE:         "close",
	SOCKTRACE_SYSCALL_POLL:          "poll",
	SOCKTRACE_SYSCALL_PPOLL:         "ppoll",
	SOCKTRACE_SYSCALL_SELECT:        "select",
	SOCKTRACE_SYSCALL_PSELECT:       "pselect",
	SOCKTRACE_SYSCALL_EPOLL_CREATE:  "epoll_create",
	SOCKTRACE_SYSCALL_EPOLL_CREATE1: "epoll_create1",
	SOCKTRACE_SYSCALL_EPOLL_CTL:     "epoll_ctl",
	SOCKTRACE_SYSCALL_EPOLL_WAIT:    "epoll_wait",
	SOCKTRACE_SYSCALL_EPOLL_PWAIT:   "epoll_pwait",
	SOCKTRACE_SYSCALL_EPOLL_PWAIT2:  "epoll_pwait2",
	SOCKTRACE_SYSCALL_SENDFILE64:    "sendfile",
	SOCKTRACE_SYSCALL_IOCTL:         "ioctl",
	SOCKTRACE_SYSCALL_SPLICE:        "splice",
	SOCKTRACE_SYSCALL_TEE:           "tee",
	SOCKTRACE_SYSCALL_DUP:           "dup",
	SOCKTRACE_SYSCALL_DUP2:          "dup2",
	SOCKTRACE_SYSCALL_DUP3:          "dup3",
	SOCKTRACE_SYSCALL_SOCKETPAIR:    "socketpair",
}

func LaunchProgram(cmd []string) (int, error) {
	if len(cmd) == 0 {
		return -1, errors.New("invalid program")
	}

	pid_ptr, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	pid := int(pid_ptr)

	if pid != 0 {
		if errno != 0 {
			return 0, os.NewSyscallError("fork", errno)
		}
		return pid, nil
	}

	_, err := syscall.Setsid()
	if err != nil {
		log.Fatalln(err.Error())
	}

	file, err := os.OpenFile(IPC_PATH, os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		log.Fatalln(err.Error())
	}

	pipeData := make([]byte, 10)
	_, err = file.Read(pipeData)

	if err != nil {
		fmt.Println(err.Error())
		return 0, err
	}

	binary, err := exec.LookPath(cmd[0])
	if err != nil {
		return 0, err
	}
	err = syscall.Exec(binary, cmd, []string{})
	return 0, err
}

func WaitProgram(pid int) (bool, int) {
	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, &rusage)

	if wpid == pid && err == nil && ws.Exited() {
		return true, ws.ExitStatus()
	}

	return false, -1
}

func TerminateProgram(pid int) error {
	process, err := os.FindProcess(pid)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	if err = process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}

		if err := process.Kill(); err != nil {
			return err
		}
	}

	return nil
}

func ReadSymbolAddress(symbol string) (uint64, error) {
	kallsyms, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return 0, err
	}
	symbols := strings.Split(string(kallsyms), "\n")
	for _, line := range symbols {
		parts := strings.Split(line, " ")
		if parts[2] == symbol {
			return strconv.ParseUint(parts[0], 16, 64)
		}

	}

	return 0, errors.New("Symbol " + symbol + " Not Found")
}

func (tracer *SockTracer) AttachMonitor(pid uint32) error {
	epoll_fops_ptr, err := ReadSymbolAddress("eventpoll_fops")
	if err != nil {
		return err
	}

	log.Printf("Address of eventpoll_fops is %x", epoll_fops_ptr)

	err = LoadSocktraceEbpfObjects(&tracer.Objs, nil)
	if err != nil {
		return err
	}

	err = tracer.Objs.TargetPids.Update(pid, uint32(1), ebpf.UpdateAny)
	if err != nil {
		return err
	}

	err = tracer.Objs.EventpollFopsPtr.Set(epoll_fops_ptr)
	if err != nil {
		return err
	}

	tracer_programs := reflect.ValueOf(tracer.Objs.SocktraceEbpfPrograms)

	for idx := range tracer_programs.NumField() {
		prog, ok := tracer_programs.Field(idx).Interface().(*ebpf.Program)
		if !ok {
			return errors.New("Invalid Field Type")
		}

		prog_info, err := prog.Info()
		if err != nil {
			return err
		}

		func_info, err := prog_info.FuncInfos()
		if err != nil {
			return err
		}

		var lnk link.Link
		prog_name := func_info[0].Func.Name

		if slices.Contains(CONTROL_PROGRAMS, prog_name) {
			lnk, err = link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntry,
			})
		} else {
			prog_name = strings.Split(prog_name, "tracepoint__syscalls__")[1]
			lnk, err = link.Tracepoint("syscalls", prog_name, prog, nil)
		}

		if err != nil {
			return err
		}

		tracer.Links = append(tracer.Links, lnk)
	}

	tracer.EventsRing = new(RingChannel[SocketEvent])
	tracer.EventsRing.Init(tracer.Objs.Events)

	tracer.ProcessRing = new(RingChannel[uint32])
	tracer.ProcessRing.Init(tracer.Objs.ProcessEvents)

	log.Println("Loaded eBPF Objects!")

	return nil
}

func (tracer *SockTracer) Close() {
	if tracer.EventsRing != nil {
		tracer.EventsRing.Close()
	}

	if tracer.ProcessRing != nil {
		tracer.ProcessRing.Close()
	}

	for _, l := range tracer.Links {
		l.Detach()
		l.Close()
	}
	tracer.Objs.Close()
}

func main() {
	var args SocktraceArgs
	log.SetPrefix("[Socktrace] ")
	log.SetFlags(log.Ldate | log.Ltime)
	flag.BoolVar(&args.help, "h", false, "Prints this help text.")
	flag.BoolVar(&args.file, "f", false, "Output Events to a CSV file.")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] program args..\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	if args.help {
		flag.Usage()
	}

	break_flag := make(chan bool)

	program_cmdline := flag.Args()

	if len(program_cmdline) == 0 {
		log.Fatalln("Program not specified!")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigs
		log.Printf("Received Signal: %s", sig.String())
		break_flag <- true
	}()

	os.Remove(IPC_PATH)
	err := syscall.Mkfifo(IPC_PATH, 0666)
	if err != nil {
		log.Fatalln(err.Error())
	}

	pid, err := LaunchProgram(program_cmdline)
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Printf("Launched Program with PID(%d): %v", pid, program_cmdline)

	var logger *SocktraceEventLog = nil
	if args.file {
		logger, err = CreateEventLoggerWithHeaders(pid)
		if err != nil {
			log.Fatalln(err.Error())
		}
		defer logger.Close()
	}

	tracer := new(SockTracer)
	err = tracer.AttachMonitor(uint32(pid))
	if err != nil {
		log.Fatalln(err)
	}
	defer tracer.Close()

	log.Println("Attached eBPF programs!")

	file, err := os.OpenFile(IPC_PATH, os.O_CREATE|os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = file.WriteString("Go")
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Started monitoring!")

loop:
	for {
		select {
		case <-break_flag:
			fmt.Println("Signal Received!")
			break loop
		case event := <-tracer.EventsRing.Channel:
			if logger != nil {
				logger.WriteEvent(&event)
			} else {
				log.Printf("%d,%d,%d,%d,%d,%s,%d\n",
					event.Cookie, event.ParentCookie, event.TimestampNs,
					event.Pid, event.Tgid, socktrace_syscalls[event.Operation],
					event.FileDescriptor)
			}
		case pid := <-tracer.ProcessRing.Channel:
			log.Printf("New Process Addeed: %d\n", pid)
		default:
			exited, exit_status := WaitProgram(pid)
			if exited {
				log.Printf("Program process(%d) exited with status=%d", pid, exit_status)
				break loop
			}
		}
	}

	if err := TerminateProgram(pid); err != nil {
		log.Fatalln("Failed terminating process", err.Error())
	}

	log.Println("Finished")
}
