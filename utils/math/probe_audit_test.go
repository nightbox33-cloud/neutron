package math_test

import (
	"testing"

	"cosmossdk.io/math"
	mathutils "github.com/neutron-org/neutron/v11/utils/math"
)

func TestAuditProbe(t *testing.T) {
	d := mathutils.NewPrecDecFromInt(math.NewInt(7))
	q := d.Quo(mathutils.NewPrecDecFromInt(math.NewInt(3)))
	if q.IsNil() {
		t.Fatal("nil")
	}
	t.Log("probe ok:", q.String())
}
