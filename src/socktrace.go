package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	MAX_PROCESSES = 256
	MAX_SOCKETS   = 64
	IPC_PATH      = "/tmp/socktrace.sock"
)

type SocktraceArgs struct {
	help     bool
	duration time.Duration
	sampling time.Duration
}

type SocktracePerfLog struct {
	pid  int
	file *os.File
}

const (
	SOCKTRACE_SYSCALL_SOCKET int = iota
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
	SOCKTRACE_SYSCALL_MAX
)

var socktrace_syscalls = map[int]string{
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
}

func CreateWithHeaders(pid int) (*SocktracePerfLog, error) {
	var err error
	perf := new(SocktracePerfLog)
	perf.pid = pid
	path := fmt.Sprintf("socktrace-%d.csv", pid)
	perf.file, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)

	if err == nil {
		_, err = perf.file.WriteString("SocketFD, PID")

		if err != nil {
			goto end
		}

		for _, val := range socktrace_syscalls {
			s := fmt.Sprintf(", %s", val)
			_, err = perf.file.WriteString(s)
			if err != nil {
				goto end
			}
		}

		perf.file.WriteString("\n")
		err = perf.file.Sync()
	}
end:
	return perf, err
}

func (perf *SocktracePerfLog) WriteMeasurement(socketfd int, pid uint32, measurement [SOCKTRACE_SYSCALL_MAX]uint32) error {
	if perf.file == nil {
		return errors.New("invalid file")
	}

	var csv strings.Builder
	substring := fmt.Sprintf("%d,%d", socketfd, pid)
	csv.WriteString(substring)
	for _, value := range measurement {
		substring = fmt.Sprintf(", %d", value)
		csv.WriteString(substring)
	}
	csv.WriteRune('\n')

	_, err := perf.file.WriteString(csv.String())
	if err != nil {
		err = perf.file.Sync()
	}
	return err
}

func (perf *SocktracePerfLog) Close() error {
	if perf.file != nil {
		return perf.file.Close()
	}

	return nil
}

func LaunchProgram(cmd []string) (int, error) {
	if len(cmd) == 0 {
		return -1, errors.New("invalid program")
	}

	pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)

	if pid != 0 {
		if errno != 0 {
			return 0, os.NewSyscallError("fork", errno)
		}
		return int(pid), nil
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

type SyscallCounters struct {
	Counters [SOCKTRACE_SYSCALL_MAX]uint32
}

func (socktrace_objects *SocktraceEbpfObjects) SetupObjects(pid uint32, valuesz uint32) (*ebpf.Collection, error) {
	processesMapSpec := ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  valuesz,
		MaxEntries: MAX_PROCESSES,
	}

	collection_spec, err := LoadSocktraceEbpf()
	if err != nil {
		return nil, err
	}

	err = collection_spec.Variables["target_pid"].Set(pid)
	if err != nil {
		return nil, err
	}

	socketsMapSpec := collection_spec.Maps["sockets"]
	socketsMapSpec.InnerMap = &processesMapSpec

	for i := range MAX_SOCKETS {
		innerMapSpec := ebpf.MapSpec{
			Name:       fmt.Sprintf("processes_%d", i),
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  valuesz,
			MaxEntries: MAX_PROCESSES,
		}

		procmap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return nil, err
		}

		socketsMapSpec.Contents = append(socketsMapSpec.Contents, ebpf.MapKV{Key: uint32(i), Value: procmap})
	}

	err = collection_spec.LoadAndAssign(socktrace_objects, nil)
	if err != nil {
		return nil, err
	}

	collection, err := ebpf.NewCollection(collection_spec)
	return collection, err
}

func AttachMonitor(pid uint32) (*SocktraceEbpfObjects, []link.Link, error) {
	var counters SyscallCounters
	var links []link.Link

	socktrace_objects := new(SocktraceEbpfObjects)
	valuesz := uint32(unsafe.Sizeof(counters))
	collection, err := socktrace_objects.SetupObjects(pid, valuesz)
	if err != nil {
		goto exit
	}

	for name, prog := range collection.Programs {
		name = strings.Split(name, "tracepoint__syscalls__")[1]
		l, err := link.Tracepoint("syscalls", name, prog, nil)
		if err != nil {
			goto exit
		}

		links = append(links, l)
	}
	log.Println("Loaded eBPF Objects!")

exit:
	return socktrace_objects, links, err
}

func (log *SocktracePerfLog) SaveMeasurement(objs *SocktraceEbpfObjects) error {
	var processes *ebpf.Map
	var key uint32
	var val SyscallCounters
	var err error

forsockets:
	for fd := range MAX_SOCKETS {
		err = objs.Sockets.Lookup(uint32(fd), &processes)
		if err != nil {
			break forsockets
		}

		mapIterator := processes.Iterate()
		for mapIterator.Next(&key, &val) {
			log.WriteMeasurement(fd, key, val.Counters)
		}

		if processes != nil {
			processes.Close()
		}
	}
	return err
}

func main() {
	var args SocktraceArgs
	log.SetPrefix("[Socktrace] ")
	log.SetFlags(log.Ldate | log.Ltime)
	flag.BoolVar(&args.help, "h", false, "Prints this help text.")
	flag.DurationVar(&args.duration, "d", 0, "Run duration.")
	flag.DurationVar(&args.sampling, "s", 0, "Set sampling period")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] program args..\n", flag.Arg(0))
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	if args.help {
		flag.Usage()
	}

	break_flag := make(chan bool, 1)

	program_cmdline := flag.Args()

	if len(program_cmdline) == 0 {
		fmt.Println("Program not specified!")
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
		log.Fatalln(err)
	}

	pid, err := LaunchProgram(program_cmdline)
	if err != nil {
		log.Fatalln(err)
	}

	if pid == 0 {
		log.Fatalln("Program process exited")
	}
	log.Printf("Launched Program with PID(%d): %v", pid, program_cmdline)

	perflogs, err := CreateWithHeaders(pid)
	if err != nil {
		log.Fatalln(err)
	}

	defer perflogs.Close()

	objs, links, err := AttachMonitor(uint32(pid))
	if err != nil {
		log.Fatalln(err)
	}
	defer objs.Close()
	log.Println("Attached eBPF programs!")

	var duration_chnl <-chan time.Time
	var sampling_chnl <-chan time.Time

	if args.duration > 0 {
		duration_chnl = time.After(args.duration)
	}

	if args.sampling > 0 {
		sampling_chnl = time.Tick(args.sampling)
	}

	file, err := os.OpenFile(IPC_PATH, os.O_CREATE|os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = file.WriteString("Go")
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Started monitoring")

loop:
	for {
		select {
		case <-break_flag:
			fmt.Println("Signal Received.")
			break loop
		case <-duration_chnl:
			log.Printf("Timeout. Exiting after %v\n", args.duration)
			fmt.Println("Timeout.")
			break loop
		case <-sampling_chnl:
			perflogs.SaveMeasurement(objs)
		default:
			var ws syscall.WaitStatus
			var rusage syscall.Rusage
			wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, &rusage)

			if wpid == pid && err == nil && ws.Exited() {
				fmt.Println("Exiting...")
				log.Printf("Program process(%d) exited with status=%d", wpid, ws.ExitStatus())
				break loop
			}
		}
	}

	perflogs.SaveMeasurement(objs)

	for _, l := range links {
		l.Close()
	}

	log.Println("Finished")
}
