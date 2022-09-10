package iptable

import "testing"

func TestParseIpTablesCmdString(t *testing.T) {
	testTable := []struct {
		value    string
		expected []string
	}{
		{"-A PREROUTING -m comment --comment \"!fw3: Custom prerouting rule chain\" -j prerouting_rule", []string{
			"-A PREROUTING",
			"-m comment",
			"--comment \"!fw3: Custom prerouting rule chain\"",
			"-j prerouting_rule",
		}},
		{"-A PREROUTING -i br-lan -m comment --comment \"!fw3\" -j zone_lan_prerouting", []string{
			"-A PREROUTING",
			"-i br-lan",
			"-m comment",
			"--comment \"!fw3\"",
			"-j zone_lan_prerouting",
		}},
		{"-A FORWARD -o br-wan -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment \"!fw3: Zone wan MTU fixing\" -j TCPMSS --clamp-mss-to-pmtu", []string{
			"-A FORWARD",
			"-o br-wan",
			"-p tcp",
			"-m tcp",
			"--tcp-flags SYN,RST SYN",
			"-m comment",
			"--comment \"!fw3: Zone wan MTU fixing\"",
			"-j TCPMSS",
			"--clamp-mss-to-pmtu",
		}},
		{"-A zone_lan_postrouting -s 10.0.0.0/16 -d 10.0.0.110/32 -p udp -m udp --dport 58444 -j SNAT --to-source 10.0.0.1 -m comment --comment \"!fw3\"", []string{
			"-A zone_lan_postrouting",
			"-s 10.0.0.0/16",
			"-d 10.0.0.110/32",
			"-p udp",
			"-m udp",
			"--dport 58444",
			"-j SNAT",
			"--to-source 10.0.0.1",
			"-m comment",
			"--comment \"!fw3\"",
		}},
	}
	for i, testVal := range testTable {
		args := ParseIpTablesCmdString(testVal.value)
		results := args.args
		if len(results) != len(testVal.expected) {
			t.Errorf("Test %d: Was expecting %d flags, got instead %d", i, len(testVal.expected), len(results))
			return
		}
		for j, result := range results {
			var finalStr string
			if result.Value == "true" {
				finalStr = result.Flag
			} else {
				finalStr = result.Flag + " " + result.Value
			}
			if finalStr != testVal.expected[j] {
				t.Errorf("Test %d: Flag at position %d was expected to be %s, got %s instead", i, j, testVal.expected[j], finalStr)
				return
			}
		}
		t.Logf("Test %d: %s is OK", i, testVal.value)
	}
}
