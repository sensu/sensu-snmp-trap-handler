package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	"github.com/sensu/sensu-go/types"
	snmp "github.com/soniah/gosnmp"
)

// Config represents the handler plugin config.
type Config struct {
	sensu.PluginConfig
	Community   string
	Host        string
	Port        int
	Version     string
	VarbindTrim int
}

const (
	// SensuEnterprisePEN is the Sensu Enterprise PEN
	SensuEnterprisePEN = "1.3.6.1.4.1.45717"
)

var (
	// ValidSNMPVersions contains the supported SNMP versions
	ValidSNMPVersions = []string{"1", "2", "2c"}

	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "sensu-snmp-trap-handler",
			Short:    "Sensu SNMP Trap Handler",
			Keyspace: "sensu.io/plugins/sensu-snmp-trap-handler/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "community",
			Env:       "SNMP_COMMUNITY",
			Argument:  "community",
			Shorthand: "c",
			Default:   "public",
			Usage:     "The SNMP Community string to use when sending traps",
			Value:     &plugin.Community,
		},
		{
			Path:      "host",
			Env:       "SNMP_HOST",
			Argument:  "host",
			Shorthand: "H",
			Default:   "127.0.0.1",
			Usage:     "The SNMP manager host address",
			Value:     &plugin.Host,
		},
		{
			Path:      "port",
			Env:       "SNMP_PORT",
			Argument:  "port",
			Shorthand: "p",
			Default:   162,
			Usage:     "The SNMP manager trap port (UDP)",
			Value:     &plugin.Port,
		},
		{
			Path:      "version",
			Env:       "SNMP_VERSION",
			Argument:  "version",
			Shorthand: "v",
			Default:   "2",
			Usage:     "The SNMP version to use (1,2,2c)",
			Value:     &plugin.Version,
		},
		{
			Path:      "varbind-trim",
			Env:       "SNMP_VARBIND_TRIM",
			Argument:  "varbind-trim",
			Shorthand: "t",
			Default:   100,
			Usage:     "The SNMP trap varbind value trim length",
			Value:     &plugin.VarbindTrim,
		},
	}
)

func main() {
	handler := sensu.NewGoHandler(&plugin.PluginConfig, options, checkArgs, executeHandler)
	handler.Execute()
}

func checkArgs(_ *types.Event) error {
	if len(plugin.Host) == 0 {
		return fmt.Errorf("--host or SNMP_HOST environment variable is required")
	}
	if !contains(ValidSNMPVersions, plugin.Version) {
		return fmt.Errorf("Invalid SNMP version, %s, specified", plugin.Version)
	}
	return nil
}

func executeHandler(event *types.Event) error {
	var checkStatus int
	snmp.Default.Target = plugin.Host
	snmp.Default.Port = uint16(plugin.Port)
	snmp.Default.Community = plugin.Community
	snmp.Default.Logger = log.New(os.Stdout, "", 0)

	switch plugin.Version {
	case "1":
		snmp.Default.Version = snmp.Version1
	case "2", "2c":
		snmp.Default.Version = snmp.Version2c
	}

	err := snmp.Default.Connect()
	if err != nil {
		return fmt.Errorf("Connect() err: %v", err)
	}
	defer snmp.Default.Conn.Close()

	eventEntryOID := fmt.Sprintf("%s.1.1.1", SensuEnterprisePEN)
	clientAddress, err := getClientIP(event)
	if err != nil {
		return fmt.Errorf("getClientIP() err: %v", err)
	}
	message := formatMessage(event)
	action := map[string]int{
		"failing":  0,
		"passing":  1,
		"flapping": 2,
	}
	if event.Check.Status > 3 {
		checkStatus = 3
	} else {
		checkStatus = int(event.Check.Status)
	}

	trap := snmp.SnmpTrap{
		Variables: []snmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.6.3.1.1.4.1.0",
				Type:  snmp.ObjectIdentifier,
				Value: SensuEnterprisePEN + ".1.0",
			},
			{
				Name:  eventEntryOID + ".1",
				Type:  snmp.OctetString,
				Value: fmt.Sprintf("%s/%s", event.Entity.Name, event.Check.Name),
			},
			{
				Name:  eventEntryOID + ".2",
				Type:  snmp.OctetString,
				Value: message,
			},
			{
				Name:  eventEntryOID + ".3",
				Type:  snmp.OctetString,
				Value: event.Entity.Name,
			},
			{
				Name:  eventEntryOID + ".4",
				Type:  snmp.OctetString,
				Value: event.Check.Name,
			},
			{
				Name:  eventEntryOID + ".5",
				Type:  snmp.Integer,
				Value: checkStatus,
			},
			{
				Name:  eventEntryOID + ".6",
				Type:  snmp.OctetString,
				Value: trimOutput(event.Check.Output),
			},
			{
				Name:  eventEntryOID + ".7",
				Type:  snmp.Integer,
				Value: int(action[event.Check.State]),
			},
			{
				Name:  eventEntryOID + ".8",
				Type:  snmp.Integer,
				Value: int(event.Check.Executed),
			},
			{
				Name:  eventEntryOID + ".9",
				Type:  snmp.Integer,
				Value: int(event.Check.Occurrences),
			},
			{
				Name:  eventEntryOID + ".10",
				Type:  snmp.OctetString,
				Value: clientAddress,
			},
		},
	}

	if plugin.Version == "1" {
		trap.Enterprise = SensuEnterprisePEN
		myip, err := getAgentIP()
		if err != nil {
			return fmt.Errorf("failed to lookup my own IP address")
		}
		trap.AgentAddress = myip
		fmt.Println(myip)
	}

	_, err = snmp.Default.SendTrap(trap)
	if err != nil {
		log.Fatalf("SendTrap() err: %v", err)
	}
	return nil
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func getClientIP(event *types.Event) (string, error) {
	for _, a := range event.Entity.System.Network.Interfaces {
		if a.Name == "lo" || contains(a.Addresses, "127.0.0.1/8") {
			continue
		}
		return strings.Split(a.Addresses[0], "/")[0], nil
	}
	return "", fmt.Errorf("failed to get client IP from entity")
}

func formatMessage(event *types.Event) string {
	var action string

	if event.Check.State == "passing" {
		action = "RESOLVED"
	} else {
		action = "ALERT"
	}

	return fmt.Sprintf("%s - %s/%s : %s", action, event.Entity.Name, event.Check.Name, trimOutput(event.Check.Output))
}

func trimOutput(output string) string {
	a := strings.TrimRight(output, "\n")

	if len(a) > plugin.VarbindTrim {
		return a[0:plugin.VarbindTrim] + "..."
	}
	return a
}

func getAgentIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("are you connected to the network?")
}
