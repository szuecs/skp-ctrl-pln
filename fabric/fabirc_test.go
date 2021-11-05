package fabric_test

import (
	"testing"

	"github.com/szuecs/skp-ctrl-pln/fabric/fabrictest"
)

func TestFabric(t *testing.T) {
	fabrictest.FixturesToTest(t, "testdata/in")
}
