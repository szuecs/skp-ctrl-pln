package fabric_test

import (
	"testing"

	"github.com/szuecs/skp-ctrl-pln/fabric/fabrictest"
)

func TestFabricFeature(t *testing.T) {
	fabrictest.FixturesToTest(t, "testdata/feature")
}
