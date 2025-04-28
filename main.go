package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"layeh.com/radius"
)

type RadiusPackage struct {
	Code          uint8
	Identifier    uint8
	Length        uint16
	Authenticator [16]uint8
	Apvs          [256]uint8
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs radius_parserObjects
	if err := loadRadius_parserObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "wlp58s0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.RadiusParser,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	reader, err := perf.NewReader(objs.RadiusEvents, os.Getpagesize())
	if err != nil {
		log.Fatal("NewReader:", err)
	}
	defer reader.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	for {
		event, err := reader.Read()
		if err != nil {
			continue
		}
		if event.LostSamples > 0 {
			continue
		}
		parseRadiusPackage(event.RawSample)
	}
}

func parseRadiusPackage(radiusPackage []byte) {
	packet, err := radius.Parse(radiusPackage, []byte(""))
	if err != nil {
		panic(err)
	}

	// Iterate over all attributes
	for _, attr := range packet.Attributes {
		fmt.Println(attr.Type, string(attr.Attribute))
		if attr.Type == radius.Type(26) {
			vendorId, vattr, err := radius.VendorSpecific(attr.Attribute)
			if err != nil {
				return
			}
			if vendorId == 1 {
				vattrs, err := radius.ParseAttributes(attr.Attribute)
			}
		}
	}
}
