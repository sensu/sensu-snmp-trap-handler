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
	assert.NoError(checkArgs(event))
	plugin.Version = "99"
	assert.Error(checkArgs(event))
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
	expectedString := formatMessage(event)
	assert.Equal(expectedString, "RESOLVED - entity1/check1 : Check Output")
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
