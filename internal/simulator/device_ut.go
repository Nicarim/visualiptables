package simulator

import "visualiptables/internal/iptable"

// device_ut = device under test.
// Simulated device which is the receiver, sender, or processor of the packet that is being sent
// It may contain internet interfaces, and contains all the iptable tables, chains and rules.

type DeviceUnderTest struct {
	interfaces []string
	tables     *[]iptable.IPTable
}

func (t *DeviceUnderTest) AddInterface(name string) {
	t.interfaces = append(t.interfaces, name)
}
