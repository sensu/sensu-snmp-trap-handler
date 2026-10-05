package main

import (
	"testing"

	snmp "github.com/gosnmp/gosnmp"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/stretchr/testify/assert"
)

/* Tests still needed:
   getClientIP - need to build event.Check with network interfaces
   executeCheck - borrow trap listener from gosnmp tests?
*/

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
