package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// var (
//     device       string = "en0"
//     snapshot_len int32  = 1024
//     promiscuous  bool   = false
//     err          error
//     timeout      time.Duration = 1 * time.Second
//     handle       *pcap.Handle
// )

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Process packet here
        fmt.Println(packet)
    }
}