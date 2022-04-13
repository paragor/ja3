// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/paragor/ja3/pkg/ja3"
	"io"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\nCreates JA3 digests for TLS client fingerprinting.\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n\nExample:\n\n[host:]# ./ja3exporter -pcap=\"/path/to/file\"\n{\"destination_ip\":\"172.217.168.67\",\"destination_port\":443,\"ja3\":\"771,49200-49196-49199-49195-49172-49162-49171-49161-159-158-57-51-157-156-53-47-10-255,0-11-10-35-13-5-15-13172,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2\",\"ja3_digest\":\"5e647d60a56d199388ae462b75b3cdad\",\"source_ip\":\"213.156.236.180\",\"source_port\":34577,\"sni\":\"www.google.ch\",\"timestamp\":1537516825571014000}\n\n")
	}
	pcap := flag.String("pcap", "", "Path to pcap file to be read")
	pcapng := flag.String("pcapng", "", "Path to pcapng file to be read")
	device := flag.String("interface", "", "Name of interface to be read (e.g. eth0)")
	filter := flag.String("filter", "", "bpf filter")
	compat := flag.Bool("c", false, "Activates compatibility mode (use this if packet does not consist of a pure ETH/IP/TCP stack)")
	flag.Parse()

	if *pcap != "" {
		// Read pcap file
		f, err := os.Open(*pcap)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		r, err := ReadPcapFile(f)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else if *pcapng != "" {
		// Read pcapng file
		f, err := os.Open(*pcapng)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		r, err := ReadPcapngFile(f)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else if *device != "" {
		// Read from interface
		r, err := ReadFromInterface(*device, *filter)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
}
// Reader provides an uniform interface when reading from different sources for the command line interface.
type Reader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// ReadPcapFile returns a reader for the supplied pcap file.
func ReadPcapFile(file *os.File) (Reader, error) {
	return pcapgo.NewReader(file)
}

// ReadPcapngFile returns a reader for the supplied pcapng file.
func ReadPcapngFile(file *os.File) (Reader, error) {
	return pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
}

// ReadFromInterface returns a handle to read from the specified interface. The snap length is set to 1600 and the
// interface is in promiscuous mode.
func ReadFromInterface(device string, filter string) (Reader, error) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

// ComputeJA3FromReader reads from reader until an io.EOF error is encountered and writes verbose information about
// the found Client Hellos in the stream in JSON format to the writer. It only supports packets consisting of a pure
// ETH/IP/TCP stack but is very fast. If your packets have a different structure, use the CompatComputeJA3FromReader
// function.
func ComputeJA3FromReader(reader Reader, writer io.Writer) error {

	// Build a selective parser which only decodes the needed layers
	var ethernet layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernet, &ipv4, &ipv6, &tcp)

	for {
		// Read packet data
		packet, ci, err := reader.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// Decode the packet with our predefined parser
		parser.DecodeLayers(packet, &decoded)
		// Check if we could decode up to the TCP layer
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTCP:

				j, err := ja3.ComputeJA3FromSegment(tcp.Payload)
				// Check if the parsing was successful, else segment is no Client Hello
				if err != nil {
					continue
				}

				// Prepare capture info for JSON marshalling
				var srcIP, dstIP string
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeIPv4:
						srcIP = ipv4.SrcIP.String()
						dstIP = ipv4.DstIP.String()
					case layers.LayerTypeIPv6:
						srcIP = ipv6.SrcIP.String()
						dstIP = ipv6.DstIP.String()
					}
				}

				err = writeJSON(dstIP, int(tcp.DstPort), srcIP, int(tcp.SrcPort), ci.Timestamp.UnixNano(), j, writer)
				if err != nil {
					return err
				}

			}
		}
	}
	return nil
}

// CompatComputeJA3FromReader has the same functionality as ComputeJA3FromReader but supports any protocol that is
// supported by the gopacket library. It is much slower than the ComputeJA3FromReader function and therefore should not
// be used unless needed.
func CompatComputeJA3FromReader(reader Reader, writer io.Writer) error {
	for {
		// Read packet data
		packetData, ci, err := reader.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true, Lazy: true})

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			j, err := ja3.ComputeJA3FromSegment(tcp.Payload)
			// Check if the parsing was successful, else segment is no Client Hello
			if err != nil {
				continue
			}

			// Prepare capture info for JSON marshalling
			src, dst := packet.NetworkLayer().NetworkFlow().Endpoints()

			err = writeJSON(dst.String(), int(tcp.DstPort), src.String(), int(tcp.SrcPort), ci.Timestamp.UnixNano(), j, writer)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// writeJSON to writer
func writeJSON(dstIP string, dstPort int, srcIP string, srcPort int, timestamp int64, j *ja3.JA3, writer io.Writer) error {
	// Use the same convention as in the official Python implementation
	js, err := json.Marshal(struct {
		DstIP     string `json:"destination_ip"`
		DstPort   int    `json:"destination_port"`
		JA3String string `json:"ja3"`
		JA3Hash   string `json:"ja3_digest"`
		SrcIP     string `json:"source_ip"`
		SrcPort   int    `json:"source_port"`
		SNI       string `json:"sni"`
		Timestamp int64  `json:"timestamp"`
	}{
		dstIP,
		dstPort,
		string(j.GetJA3String()),
		j.GetJA3Hash(),
		srcIP,
		srcPort,
		j.GetSNI(),
		timestamp,
	})
	if err != nil {
		return err
	}

	// Write the JSON to the writer
	writer.Write(js)
	writer.Write([]byte("\n"))
	return nil
}
