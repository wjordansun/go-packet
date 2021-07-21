package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func realCallback(payload *nfqueue.Payload) int {
	// Decode a packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	//Log Initial State
	fmt.Printf("  id: %d\n", payload.Id)
	fmt.Println(hex.Dump(payload.Data))
	if app := packet.ApplicationLayer(); app != nil {
		if strings.Contains(string(app.Payload()), "magic string") {
			// modify payload of application layer
			*packet.ApplicationLayer().(*gopacket.Payload) = bytes.ReplaceAll(app.Payload(), []byte("magic string"), []byte("modified value"))
			// if its tcp we need to tell it which network layer is being used
			// to be able to handle multiple protocols we can add a if clause around this
			packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			// Serialize Packet to get raw bytes
			if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
				log.Fatalln(err)
			}

			packetBytes := buffer.Bytes()
			
			//Pretty color diff on the hexdump
			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(hex.Dump(payload.Data), hex.Dump(packetBytes), true)
			fmt.Println(dmp.DiffPrettyText(diffs))
			//Set the packet verdict as modified
			payload.SetVerdictModified(nfqueue.NF_ACCEPT, packetBytes)
			return 0
		}
	}
	fmt.Println("-- ")
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func main() {
	//Create go nfqueue
	q := new(nfqueue.Queue)
	//Set callback for queue
	q.SetCallback(realCallback)
	//Initialize queue
	q.Init()
	//Generic reset for bind
	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)
	//Create nfqueue "0"
	q.CreateQueue(0)

	//Set iptables rule to route packets from sourc eport 9999 to queue number 0
	cmd := exec.Command("iptables", "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--source-port", "9999", "-j", "NFQUEUE", "--queue-num", "0")
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdout))
	}

	//Listener for CNTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	log.SetOutput(ioutil.Discard)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.StopLoop()
		}
	}()

	// XXX Drop privileges here

	q.Loop()
	q.DestroyQueue()
	q.Close()

	//Remove iptables rules that route packets into nfqueue
	unroute := exec.Command("iptables", "-F", "-t", "raw")
	stdoutUnroute, err := unroute.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdoutUnroute))
	}

	os.Exit(0)
}