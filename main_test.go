package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	snmp "github.com/gosnmp/gosnmp"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/stretchr/testify/assert"
)

func TestCheckArgs(t *testing.T) {
	assert := assert.New(t)
	event := corev2.FixtureEvent("entity1", "check1")
	plugin.Version = "2"
	plugin.Host = "localhost"
	plugin.MessageTemplate = "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}"
	assert.NoError(checkArgs(event))
	plugin.Version = "99"
	assert.Error(checkArgs(event))
	plugin.Version = "2"
}

func resetSNMPv3PluginFields() {
	plugin.Version = "2"
	plugin.SecurityLevel = ""
	plugin.Username = ""
	plugin.AuthProtocol = ""
	plugin.AuthPassphrase = ""
	plugin.PrivProtocol = ""
	plugin.PrivPassphrase = ""
	plugin.EngineID = ""
}

func TestCheckArgsSNMPv3(t *testing.T) {
	assert := assert.New(t)
	event := corev2.FixtureEvent("entity1", "check1")
	defer resetSNMPv3PluginFields()

	plugin.Host = "localhost"
	plugin.MessageTemplate = "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}"
	plugin.Version = "3"

	// missing username
	plugin.SecurityLevel = "authPriv"
	plugin.Username = ""
	plugin.EngineID = "800012fe03"
	plugin.AuthProtocol = "SHA"
	plugin.AuthPassphrase = "authpass1"
	plugin.PrivProtocol = "AES"
	plugin.PrivPassphrase = "privpass1"
	assert.Error(checkArgs(event))

	// missing engine-id
	plugin.Username = "sensu"
	plugin.EngineID = ""
	assert.Error(checkArgs(event))

	// invalid engine-id hex
	plugin.EngineID = "not-hex"
	assert.Error(checkArgs(event))

	// invalid security level
	plugin.EngineID = "800012fe03"
	plugin.SecurityLevel = "bogus"
	assert.Error(checkArgs(event))

	// missing auth passphrase for authNoPriv
	plugin.SecurityLevel = "authNoPriv"
	plugin.AuthPassphrase = ""
	assert.Error(checkArgs(event))

	// missing priv passphrase for authPriv
	plugin.SecurityLevel = "authPriv"
	plugin.AuthPassphrase = "authpass1"
	plugin.PrivPassphrase = ""
	assert.Error(checkArgs(event))

	// fully valid authPriv config
	plugin.PrivPassphrase = "privpass1"
	assert.NoError(checkArgs(event))

	// fully valid noAuthNoPriv config only requires username/engine-id
	plugin.SecurityLevel = "noAuthNoPriv"
	assert.NoError(checkArgs(event))
}

func TestDecodeEngineID(t *testing.T) {
	assert := assert.New(t)

	decoded, err := decodeEngineID("800012fe03")
	assert.NoError(err)
	assert.Equal([]byte{0x80, 0x00, 0x12, 0xfe, 0x03}, []byte(decoded))

	decoded, err = decodeEngineID("0x800012FE03")
	assert.NoError(err)
	assert.Equal([]byte{0x80, 0x00, 0x12, 0xfe, 0x03}, []byte(decoded))

	_, err = decodeEngineID("not-hex")
	assert.Error(err)
}

func TestDecodeEngineIDLengthLimits(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"1 byte", "80", true},
		{"4 bytes is below the minimum", "80000001", true},
		{"5 bytes is the minimum", "8000000001", false},
		{"11 bytes vendor style", "800000090300123456789a", false},
		{"32 bytes is the maximum", strings.Repeat("ab", 32), false},
		{"33 bytes is above the maximum", strings.Repeat("ab", 33), true},
		{"0x prefix counts only the hex digits", "0x8000000001", false},
		{"0x prefix with 4 bytes", "0x80000001", true},
		{"odd number of hex digits", "800000000", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeEngineID(test.input)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(decoded), 5)
			assert.LessOrEqual(t, len(decoded), 32)
		})
	}

	_, err := decodeEngineID("80000001")
	assert.Contains(t, err.Error(), "5 to 32 bytes")
	assert.Contains(t, err.Error(), "got 4 bytes")
}

func TestCheckArgsSNMPv3RejectsOutOfRangeEngineID(t *testing.T) {
	defer resetSNMPv3PluginFields()
	event := corev2.FixtureEvent("entity1", "check1")
	plugin.Host = "localhost"
	plugin.MessageTemplate = "{{.Check.Name}}"
	plugin.Version = "3"
	plugin.SecurityLevel = "noAuthNoPriv"
	plugin.Username = "sensu"

	plugin.EngineID = "80000001"
	assert.Error(t, checkArgs(event))
	plugin.EngineID = strings.Repeat("ab", 33)
	assert.Error(t, checkArgs(event))
	plugin.EngineID = "8000000001"
	assert.NoError(t, checkArgs(event))
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1":           "127.0.0.1",
		"snmp.example.com":    "snmp.example.com",
		"fd00:dead:beef::2":   "fd00:dead:beef::2",
		"[fd00:dead:beef::2]": "fd00:dead:beef::2",
		"[::1]":               "::1",
		"[":                   "[",
		"]":                   "]",
		"[]":                  "",
		"":                    "",
		"[abc":                "[abc",
		"abc]":                "abc]",
	}
	for in, want := range tests {
		assert.Equal(t, want, normalizeHost(in), "input %q", in)
	}
}

func TestExecuteHandlerIPv6Hosts(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	probe.Close()

	for _, host := range []string{"::1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			conn, err := net.ListenPacket("udp6", "[::1]:0")
			assert.NoError(t, err)
			port := conn.LocalAddr().(*net.UDPAddr).Port
			conn.Close()

			received := make(chan trapResult, 4)
			tl := snmp.NewTrapListener()
			tl.Params = &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)}
			tl.OnNewTrap = func(p *snmp.SnmpPacket, _ *net.UDPAddr) { received <- trapResult{packet: p} }
			go func() { _ = tl.Listen(fmt.Sprintf("[::1]:%d", port)) }()
			select {
			case <-tl.Listening():
			case <-time.After(5 * time.Second):
				t.Fatal("trap listener did not start")
			}
			defer tl.Close()

			resetPluginForSend(port)
			plugin.Version = "2c"
			plugin.Host = host

			assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))
			vars := varbinds(waitForTrap(t, received))
			assert.Equal(t, "entity1/check1", vars[SensuEnterprisePEN+".1.1.1.1"])
		})
	}
}

func TestMapAuthProtocol(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(snmp.MD5, mapAuthProtocol("MD5"))
	assert.Equal(snmp.SHA, mapAuthProtocol("SHA"))
	assert.Equal(snmp.NoAuth, mapAuthProtocol("bogus"))
}

func TestMapPrivProtocol(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(snmp.DES, mapPrivProtocol("DES"))
	assert.Equal(snmp.AES, mapPrivProtocol("AES"))
	assert.Equal(snmp.NoPriv, mapPrivProtocol("bogus"))
}

func TestMapMsgFlags(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(snmp.NoAuthNoPriv, mapMsgFlags("noAuthNoPriv"))
	assert.Equal(snmp.AuthNoPriv, mapMsgFlags("authNoPriv"))
	assert.Equal(snmp.AuthPriv, mapMsgFlags("authPriv"))
	assert.Equal(snmp.NoAuthNoPriv, mapMsgFlags("bogus"))
}

func TestConfigureSNMPv3SecurityLevels(t *testing.T) {
	originalPlugin := plugin
	originalVersion := snmp.Default.Version
	originalSecurityModel := snmp.Default.SecurityModel
	originalMsgFlags := snmp.Default.MsgFlags
	originalContextName := snmp.Default.ContextName
	originalSecurityParameters := snmp.Default.SecurityParameters
	defer func() {
		plugin = originalPlugin
		snmp.Default.Version = originalVersion
		snmp.Default.SecurityModel = originalSecurityModel
		snmp.Default.MsgFlags = originalMsgFlags
		snmp.Default.ContextName = originalContextName
		snmp.Default.SecurityParameters = originalSecurityParameters
	}()

	tests := []struct {
		securityLevel string
		msgFlags      snmp.SnmpV3MsgFlags
		authProtocol  snmp.SnmpV3AuthProtocol
		privProtocol  snmp.SnmpV3PrivProtocol
	}{
		{"noAuthNoPriv", snmp.NoAuthNoPriv, snmp.NoAuth, snmp.NoPriv},
		{"authNoPriv", snmp.AuthNoPriv, snmp.SHA, snmp.NoPriv},
		{"authPriv", snmp.AuthPriv, snmp.SHA, snmp.AES},
	}

	for _, test := range tests {
		t.Run(test.securityLevel, func(t *testing.T) {
			plugin.Version = "3"
			plugin.SecurityLevel = test.securityLevel
			plugin.Username = "sensu"
			plugin.AuthProtocol = "SHA"
			plugin.AuthPassphrase = "authpass1"
			plugin.PrivProtocol = "AES"
			plugin.PrivPassphrase = "privpass1"
			plugin.EngineID = "800012fe03"

			assert.NoError(t, configureSNMPv3())
			assert.Equal(t, test.msgFlags, snmp.Default.MsgFlags)
			securityParameters := snmp.Default.SecurityParameters.(*snmp.UsmSecurityParameters)
			assert.Equal(t, test.authProtocol, securityParameters.AuthenticationProtocol)
			assert.Equal(t, test.privProtocol, securityParameters.PrivacyProtocol)
		})
	}
}

func TestGetClientIP(t *testing.T) {
	assert := assert.New(t)
	event := corev2.FixtureEvent("entity1", "check1")
	clientAddress, err := getClientIP(event)
	assert.NoError(err)
	assert.Equal(clientAddress, "127.0.0.1")
	event.Entity.System.Network.Interfaces[0].Name = "lo"
	clientAddress, err = getClientIP(event)
	assert.Error(err)
	assert.Equal(clientAddress, "failed to get client IP from entity")
	event.Entity.System.Network.Interfaces[0].Name = "eth0"
	event.Entity.System.Network.Interfaces[0].Addresses[0] = "127.0.0.1/8"
	clientAddress, err = getClientIP(event)
	assert.Error(err)
	assert.Equal(clientAddress, "failed to get client IP from entity")
	networkInterface := corev2.NetworkInterface{
		Name: "eth1",
		MAC:  "attack of the",
		Addresses: []string{
			"10.10.10.1",
		},
	}
	assert.Equal(networkInterface.Addresses[0], "10.10.10.1")
	event.Entity.System.Network.Interfaces = append(event.Entity.System.Network.Interfaces, networkInterface)
	clientAddress, err = getClientIP(event)
	assert.NoError(err)
	assert.Equal(clientAddress, "10.10.10.1")
}

func TestGetClientIPSkipsInterfacesWithoutAddresses(t *testing.T) {
	event := corev2.FixtureEvent("entity1", "check1")
	event.Entity.System.Network.Interfaces = []corev2.NetworkInterface{
		{Name: "lo0", Addresses: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "gif0", Addresses: nil},
		{Name: "anpi0", MAC: "b2:d1:55:3a:1f:b2", Addresses: []string{}},
	}

	clientAddress, err := getClientIP(event)
	assert.Error(t, err)
	assert.Equal(t, "failed to get client IP from entity", clientAddress)

	event.Entity.System.Network.Interfaces = append(event.Entity.System.Network.Interfaces,
		corev2.NetworkInterface{Name: "en0", Addresses: []string{"192.168.1.20/24"}})

	clientAddress, err = getClientIP(event)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.20", clientAddress)
}

func TestContains(t *testing.T) {
	assert := assert.New(t)
	a := []string{"here", "there", "everywhere"}
	assert.True(contains(a, "there"))
	assert.False(contains(a, "nowhere"))
}

func TestFormatMessage(t *testing.T) {
	assert := assert.New(t)
	event := corev2.FixtureEvent("entity1", "check1")
	event.Check.State = "passing"
	event.Check.Output = "Check Output"
	plugin.VarbindTrim = 100
	plugin.MessageTemplate = "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}"
	expectedString, err := formatMessage(event)
	assert.NoError(err)
	assert.Equal(expectedString, "passing - entity1/check1 : Check Output")
}

func TestTrimOutput(t *testing.T) {
	assert := assert.New(t)
	plugin.VarbindTrim = 32
	stringToTrim := "This is less than 32 characters"
	assert.Equal(stringToTrim, trimOutput(stringToTrim))
	plugin.VarbindTrim = 20
	stringToTrim = "This is more than 32 characters"
	assert.Equal("This is more than 32...", trimOutput(stringToTrim))
}

type trapResult struct {
	packet *snmp.SnmpPacket
}

// startTrapListener runs a gosnmp trap listener on a free UDP port and returns
// its port and a channel that receives every trap it decodes.
func startTrapListener(t *testing.T, params *snmp.GoSNMP) (int, <-chan trapResult) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()

	received := make(chan trapResult, 8)
	tl := snmp.NewTrapListener()
	tl.Params = params
	tl.OnNewTrap = func(p *snmp.SnmpPacket, _ *net.UDPAddr) {
		received <- trapResult{packet: p}
	}
	go func() { _ = tl.Listen(fmt.Sprintf("127.0.0.1:%d", port)) }()
	select {
	case <-tl.Listening():
	case <-time.After(5 * time.Second):
		t.Fatal("trap listener did not start")
	}
	t.Cleanup(tl.Close)
	return port, received
}

func waitForTrap(t *testing.T, received <-chan trapResult) *snmp.SnmpPacket {
	t.Helper()
	select {
	case r := <-received:
		return r.packet
	case <-time.After(5 * time.Second):
		t.Fatal("no trap received")
		return nil
	}
}

func expectNoTrap(t *testing.T, received <-chan trapResult) {
	t.Helper()
	select {
	case <-received:
		t.Fatal("unexpected trap received")
	case <-time.After(500 * time.Millisecond):
	}
}

func varbinds(p *snmp.SnmpPacket) map[string]interface{} {
	out := map[string]interface{}{}
	for _, v := range p.Variables {
		val := v.Value
		if b, ok := val.([]byte); ok {
			val = string(b)
		}
		out[strings.TrimPrefix(v.Name, ".")] = val
	}
	return out
}

func resetPluginForSend(port int) {
	resetSNMPv3PluginFields()
	plugin.Host = "127.0.0.1"
	plugin.Port = port
	plugin.Community = "public"
	plugin.VarbindTrim = 100
	plugin.MessageTemplate = "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}"
}

func sendEvent(status uint32, state, output string) *corev2.Event {
	event := corev2.FixtureEvent("entity1", "check1")
	event.Check.Status = status
	event.Check.State = state
	event.Check.Output = output
	event.Check.Occurrences = 7
	event.Entity.System.Network.Interfaces = []corev2.NetworkInterface{
		{Name: "lo0", Addresses: []string{"127.0.0.1/8"}},
		{Name: "gif0"},
		{Name: "en0", Addresses: []string{"192.168.1.20/24"}},
	}
	return event
}

func TestExecuteHandlerSendsTrap(t *testing.T) {
	for _, version := range []string{"1", "2", "2c"} {
		t.Run("v"+version, func(t *testing.T) {
			port, received := startTrapListener(t, &snmp.GoSNMP{
				Version:   snmp.Version2c,
				Community: "public",
				Logger:    snmp.NewLogger(nil),
			})
			resetPluginForSend(port)
			plugin.Version = version

			assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))

			vars := varbinds(waitForTrap(t, received))
			base := SensuEnterprisePEN + ".1.1.1"
			assert.Equal(t, "entity1/check1", vars[base+".1"])
			assert.Equal(t, "failing - entity1/check1 : boom", vars[base+".2"])
			assert.Equal(t, "entity1", vars[base+".3"])
			assert.Equal(t, "check1", vars[base+".4"])
			assert.EqualValues(t, 2, vars[base+".5"])
			assert.Equal(t, "boom", vars[base+".6"])
			assert.EqualValues(t, 0, vars[base+".7"])
			assert.EqualValues(t, 7, vars[base+".9"])
			assert.Equal(t, "192.168.1.20", vars[base+".10"])
		})
	}
}

func TestExecuteHandlerStatusAndActionMapping(t *testing.T) {
	tests := []struct {
		name           string
		status         uint32
		state          string
		expectedStatus int
		expectedAction int
	}{
		{"ok passing", 0, "passing", 0, 1},
		{"warning failing", 1, "failing", 1, 0},
		{"critical failing", 2, "failing", 2, 0},
		{"unknown", 3, "failing", 3, 0},
		{"status above 3 is clamped", 7, "failing", 3, 0},
		{"flapping", 2, "flapping", 2, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)})
			resetPluginForSend(port)
			plugin.Version = "2c"

			assert.NoError(t, executeHandler(sendEvent(test.status, test.state, "out")))

			vars := varbinds(waitForTrap(t, received))
			base := SensuEnterprisePEN + ".1.1.1"
			assert.EqualValues(t, test.expectedStatus, vars[base+".5"])
			assert.EqualValues(t, test.expectedAction, vars[base+".7"])
		})
	}
}

func TestExecuteHandlerTrimsLongOutput(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "2c"
	plugin.VarbindTrim = 20

	long := "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
	assert.NoError(t, executeHandler(sendEvent(2, "failing", long)))

	vars := varbinds(waitForTrap(t, received))
	assert.Equal(t, long[:20]+"...", vars[SensuEnterprisePEN+".1.1.1.6"])
}

func TestExecuteHandlerUsesCommunity(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "secret123", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "2c"
	plugin.Community = "secret123"

	assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))
	assert.Equal(t, "secret123", waitForTrap(t, received).Community)
}

func TestExecuteHandlerV1SetsEnterpriseAndAgentAddress(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version1, Community: "public", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "1"

	assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))

	packet := waitForTrap(t, received)
	assert.Equal(t, snmp.Version1, packet.Version)
	assert.Equal(t, SensuEnterprisePEN, strings.TrimPrefix(packet.Enterprise, "."))
	assert.NotNil(t, net.ParseIP(packet.AgentAddress), "agent address %q should be an IP", packet.AgentAddress)
}

func TestExecuteHandlerCustomTemplate(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "2c"
	plugin.MessageTemplate = "CUSTOM {{.Entity.Name}} is {{.Check.Status}}"

	assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))

	vars := varbinds(waitForTrap(t, received))
	assert.Equal(t, "CUSTOM entity1 is 2", vars[SensuEnterprisePEN+".1.1.1.2"])
}

func TestExecuteHandlerBadTemplateReturnsError(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "2c"
	plugin.MessageTemplate = "{{.Nope.Missing}}"

	assert.Error(t, executeHandler(sendEvent(2, "failing", "boom")))
	expectNoTrap(t, received)
}

func TestExecuteHandlerConnectFailureReturnsError(t *testing.T) {
	resetPluginForSend(162)
	plugin.Version = "2c"
	plugin.Host = "no-such-host.invalid"

	err := executeHandler(sendEvent(2, "failing", "boom"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Connect() err")
}

func TestGetAgentIP(t *testing.T) {
	ip, err := getAgentIP()
	if err != nil {
		t.Skipf("no non-loopback IPv4 address on this machine: %v", err)
	}
	assert.NotNil(t, net.ParseIP(ip))
}

const testEngineID = "800012fe03"

func v3Listener(t *testing.T, sp *snmp.UsmSecurityParameters) (int, <-chan trapResult) {
	t.Helper()
	table := snmp.NewSnmpV3SecurityParametersTable(snmp.NewLogger(nil))
	assert.NoError(t, table.Add(sp.UserName, sp))
	return startTrapListener(t, &snmp.GoSNMP{
		Version:                     snmp.Version3,
		SecurityModel:               snmp.UserSecurityModel,
		MsgFlags:                    snmp.AuthPriv,
		SecurityParameters:          sp,
		TrapSecurityParametersTable: table,
		Logger:                      snmp.NewLogger(nil),
	})
}

func receiverUser(name string, auth snmp.SnmpV3AuthProtocol, authPass string, priv snmp.SnmpV3PrivProtocol, privPass string) *snmp.UsmSecurityParameters {
	engineID, _ := decodeEngineID(testEngineID)
	return &snmp.UsmSecurityParameters{
		UserName:                 name,
		AuthenticationProtocol:   auth,
		AuthenticationPassphrase: authPass,
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        privPass,
		AuthoritativeEngineID:    engineID,
	}
}

func TestExecuteHandlerSNMPv3(t *testing.T) {
	tests := []struct {
		name     string
		receiver *snmp.UsmSecurityParameters
		level    string
		username string
		authProt string
		authPass string
		privProt string
		privPass string
	}{
		{"authPriv SHA AES", receiverUser("u1", snmp.SHA, "authpass123", snmp.AES, "privpass123"), "authPriv", "u1", "SHA", "authpass123", "AES", "privpass123"},
		{"authPriv MD5 DES", receiverUser("u2", snmp.MD5, "authpass123", snmp.DES, "privpass123"), "authPriv", "u2", "MD5", "authpass123", "DES", "privpass123"},
		{"authNoPriv SHA", receiverUser("u3", snmp.SHA, "authpass123", snmp.NoPriv, ""), "authNoPriv", "u3", "SHA", "authpass123", "", ""},
		{"noAuthNoPriv", receiverUser("u4", snmp.NoAuth, "", snmp.NoPriv, ""), "noAuthNoPriv", "u4", "", "", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, received := v3Listener(t, test.receiver)
			resetPluginForSend(port)
			plugin.Version = "3"
			plugin.SecurityLevel = test.level
			plugin.Username = test.username
			plugin.AuthProtocol = test.authProt
			plugin.AuthPassphrase = test.authPass
			plugin.PrivProtocol = test.privProt
			plugin.PrivPassphrase = test.privPass
			plugin.EngineID = testEngineID
			defer func() { snmp.Default.SecurityParameters = nil }()

			assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))

			packet := waitForTrap(t, received)
			assert.Equal(t, snmp.Version3, packet.Version)
			assert.Equal(t, "entity1/check1", varbinds(packet)[SensuEnterprisePEN+".1.1.1.1"])
		})
	}
}

func TestExecuteHandlerSNMPv3WrongCredentialsAreNotAccepted(t *testing.T) {
	receiver := func() *snmp.UsmSecurityParameters {
		return receiverUser("u1", snmp.SHA, "authpass123", snmp.AES, "privpass123")
	}
	tests := []struct {
		name     string
		username string
		authPass string
		privPass string
	}{
		{"wrong auth passphrase", "u1", "WRONGAUTH123", "privpass123"},
		{"wrong privacy passphrase", "u1", "authpass123", "WRONGPRIV123"},
		{"unknown user", "nobody", "authpass123", "privpass123"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, received := v3Listener(t, receiver())
			resetPluginForSend(port)
			plugin.Version = "3"
			plugin.SecurityLevel = "authPriv"
			plugin.Username = test.username
			plugin.AuthProtocol = "SHA"
			plugin.AuthPassphrase = test.authPass
			plugin.PrivProtocol = "AES"
			plugin.PrivPassphrase = test.privPass
			plugin.EngineID = testEngineID
			defer func() { snmp.Default.SecurityParameters = nil }()

			assert.NoError(t, executeHandler(sendEvent(2, "failing", "boom")))
			expectNoTrap(t, received)
		})
	}
}

func TestExecuteHandlerSendFailureReturnsError(t *testing.T) {
	port, received := startTrapListener(t, &snmp.GoSNMP{Version: snmp.Version2c, Community: "public", Logger: snmp.NewLogger(nil)})
	resetPluginForSend(port)
	plugin.Version = "2c"
	plugin.VarbindTrim = 200000

	err := executeHandler(sendEvent(2, "failing", strings.Repeat("z", 100000)))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SendTrap() err")
	expectNoTrap(t, received)
}
