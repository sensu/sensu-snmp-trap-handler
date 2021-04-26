package main

import (
	"testing"

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
