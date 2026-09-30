package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	snmp "github.com/gosnmp/gosnmp"
	"github.com/sensu/sensu-go/types"
	"github.com/sensu/sensu-plugin-sdk/sensu"
	"github.com/sensu/sensu-plugin-sdk/templates"
)

// Config represents the handler plugin config.
type Config struct {
	sensu.PluginConfig
	Community       string
	Host            string
	Port            int
	Version         string
	VarbindTrim     int
	MessageTemplate string
	SecurityLevel   string
	Username        string
	AuthProtocol    string
	AuthPassphrase  string
	PrivProtocol    string
	PrivPassphrase  string
	ContextName     string
	EngineID        string
}

const (
	// SensuEnterprisePEN is the Sensu Enterprise PEN
	SensuEnterprisePEN = "1.3.6.1.4.1.45717"
)

var (
	// ValidSNMPVersions contains the supported SNMP versions
	ValidSNMPVersions = []string{"1", "2", "2c", "3"}

	// ValidSecurityLevels contains the supported SNMPv3 security levels
	ValidSecurityLevels = []string{"noAuthNoPriv", "authNoPriv", "authPriv"}

	// ValidAuthProtocols contains the supported SNMPv3 authentication protocols
	ValidAuthProtocols = []string{"MD5", "SHA"}

	// ValidPrivProtocols contains the supported SNMPv3 privacy protocols
	ValidPrivProtocols = []string{"DES", "AES"}

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
			Usage:     "The SNMP version to use (1,2,2c,3)",
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
		{
			Path:      "message-template",
			Env:       "SNMP_MESSAGE_TEMPLATE",
			Argument:  "message-template",
			Shorthand: "m",
			Default:   "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}",
			Usage:     "The template for the SNMP message",
			Value:     &plugin.MessageTemplate,
		},
		{
			Path:     "security-level",
			Env:      "SNMP_SECURITY_LEVEL",
			Argument: "security-level",
			Default:  "authPriv",
			Usage:    "The SNMPv3 security level to use (noAuthNoPriv, authNoPriv, authPriv)",
			Value:    &plugin.SecurityLevel,
		},
		{
			Path:     "username",
			Env:      "SNMP_USERNAME",
			Argument: "username",
			Default:  "",
			Usage:    "The SNMPv3 security username",
			Value:    &plugin.Username,
		},
		{
			Path:     "auth-protocol",
			Env:      "SNMP_AUTH_PROTOCOL",
			Argument: "auth-protocol",
			Default:  "SHA",
			Usage:    "The SNMPv3 authentication protocol to use (MD5, SHA)",
			Value:    &plugin.AuthProtocol,
		},
		{
			Path:     "auth-passphrase",
			Env:      "SNMP_AUTH_PASSPHRASE",
			Argument: "auth-passphrase",
			Default:  "",
			Usage:    "The SNMPv3 authentication passphrase",
			Value:    &plugin.AuthPassphrase,
			Secret:   true,
		},
		{
			Path:     "priv-protocol",
			Env:      "SNMP_PRIV_PROTOCOL",
			Argument: "priv-protocol",
			Default:  "AES",
			Usage:    "The SNMPv3 privacy protocol to use (DES, AES)",
			Value:    &plugin.PrivProtocol,
		},
		{
			Path:     "priv-passphrase",
			Env:      "SNMP_PRIV_PASSPHRASE",
			Argument: "priv-passphrase",
			Default:  "",
			Usage:    "The SNMPv3 privacy passphrase",
			Value:    &plugin.PrivPassphrase,
			Secret:   true,
		},
		{
			Path:     "context-name",
			Env:      "SNMP_CONTEXT_NAME",
			Argument: "context-name",
			Default:  "",
			Usage:    "The SNMPv3 context name",
			Value:    &plugin.ContextName,
		},
		{
			Path:     "engine-id",
			Env:      "SNMP_ENGINE_ID",
			Argument: "engine-id",
			Default:  "",
			Usage:    "The SNMPv3 authoritative engine ID (hex string, e.g. 800012fe03) of this handler; required for SNMPv3 since engine discovery cannot be performed for traps",
			Value:    &plugin.EngineID,
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
	if len(plugin.MessageTemplate) == 0 {
		return fmt.Errorf("--message-template or SNMP_MESSAGE_TEMPLATE environment variable is required")
	}
	if !contains(ValidSNMPVersions, plugin.Version) {
		return fmt.Errorf("Invalid SNMP version, %s, specified", plugin.Version)
	}
	if plugin.Version == "3" {
		return checkSNMPv3Args()
	}
	return nil
}

func checkSNMPv3Args() error {
	if !contains(ValidSecurityLevels, plugin.SecurityLevel) {
		return fmt.Errorf("Invalid SNMPv3 security level, %s, specified", plugin.SecurityLevel)
	}
	if len(plugin.Username) == 0 {
		return fmt.Errorf("--username or SNMP_USERNAME environment variable is required for SNMPv3")
	}
	if len(plugin.EngineID) == 0 {
		return fmt.Errorf("--engine-id or SNMP_ENGINE_ID environment variable is required for SNMPv3")
	}
	if _, err := decodeEngineID(plugin.EngineID); err != nil {
		return err
	}
	if plugin.SecurityLevel == "authNoPriv" || plugin.SecurityLevel == "authPriv" {
		if !contains(ValidAuthProtocols, plugin.AuthProtocol) {
			return fmt.Errorf("Invalid SNMPv3 auth protocol, %s, specified", plugin.AuthProtocol)
		}
		if len(plugin.AuthPassphrase) == 0 {
			return fmt.Errorf("--auth-passphrase or SNMP_AUTH_PASSPHRASE environment variable is required for security level %s", plugin.SecurityLevel)
		}
	}
	if plugin.SecurityLevel == "authPriv" {
		if !contains(ValidPrivProtocols, plugin.PrivProtocol) {
			return fmt.Errorf("Invalid SNMPv3 priv protocol, %s, specified", plugin.PrivProtocol)
		}
		if len(plugin.PrivPassphrase) == 0 {
			return fmt.Errorf("--priv-passphrase or SNMP_PRIV_PASSPHRASE environment variable is required for security level authPriv")
		}
	}
	return nil
}

// configureSNMPv3 sets up the USM security parameters for an SNMPv3 trap.
//
// The AuthoritativeEngineID must be provided explicitly (--engine-id) rather
// than discovered, since this handler is the notification originator (not an
// agent being polled) and SendTrap never waits for a reply to negotiate one.
func configureSNMPv3() error {
	engineID, err := decodeEngineID(plugin.EngineID)
	if err != nil {
		return err
	}

	snmp.Default.Version = snmp.Version3
	snmp.Default.SecurityModel = snmp.UserSecurityModel
	snmp.Default.MsgFlags = mapMsgFlags(plugin.SecurityLevel)
	snmp.Default.ContextName = plugin.ContextName
	snmp.Default.SecurityParameters = &snmp.UsmSecurityParameters{
		UserName:                 plugin.Username,
		AuthenticationProtocol:   mapAuthProtocol(plugin.AuthProtocol),
		AuthenticationPassphrase: plugin.AuthPassphrase,
		PrivacyProtocol:          mapPrivProtocol(plugin.PrivProtocol),
		PrivacyPassphrase:        plugin.PrivPassphrase,
		AuthoritativeEngineID:    engineID,
	}
	return nil
}

// decodeEngineID converts a hex-encoded engine ID (optionally 0x-prefixed) into
// the raw byte string gosnmp expects for AuthoritativeEngineID/ContextEngineID.
func decodeEngineID(engineID string) (string, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(engineID), "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid --engine-id value, must be a hex string: %v", err)
	}
	return string(decoded), nil
}

func mapAuthProtocol(protocol string) snmp.SnmpV3AuthProtocol {
	switch protocol {
	case "MD5":
		return snmp.MD5
	case "SHA":
		return snmp.SHA
	default:
		return snmp.NoAuth
	}
}

func mapPrivProtocol(protocol string) snmp.SnmpV3PrivProtocol {
	switch protocol {
	case "DES":
		return snmp.DES
	case "AES":
		return snmp.AES
	default:
		return snmp.NoPriv
	}
}

func mapMsgFlags(securityLevel string) snmp.SnmpV3MsgFlags {
	switch securityLevel {
	case "authNoPriv":
		return snmp.AuthNoPriv
	case "authPriv":
		return snmp.AuthPriv
	default:
		return snmp.NoAuthNoPriv
	}
}

func executeHandler(event *types.Event) error {
	var checkStatus int
	snmp.Default.Target = plugin.Host
	snmp.Default.Port = uint16(plugin.Port)
	snmp.Default.Community = plugin.Community
	snmp.Default.Logger = snmp.NewLogger(log.New(os.Stdout, "", 0))

	switch plugin.Version {
	case "1":
		snmp.Default.Version = snmp.Version1
	case "2", "2c":
		snmp.Default.Version = snmp.Version2c
	case "3":
		if err := configureSNMPv3(); err != nil {
			return err
		}
	}

	err := snmp.Default.Connect()
	if err != nil {
		return fmt.Errorf("Connect() err: %v", err)
	}
	defer snmp.Default.Conn.Close()

	eventEntryOID := fmt.Sprintf("%s.1.1.1", SensuEnterprisePEN)
	clientAddress, _ := getClientIP(event)
	message, err := formatMessage(event)
	if err != nil {
		return fmt.Errorf("formatMessage error: %v", err)
	}
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
	return "failed to get client IP from entity", fmt.Errorf("failed to get client IP from entity")
}

func formatMessage(event *types.Event) (string, error) {
	message, err := templates.EvalTemplate("message", plugin.MessageTemplate, event)
	if err != nil {
		return "", fmt.Errorf("failed to format message: %v", err)
	}

	return trimOutput(message), nil
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
