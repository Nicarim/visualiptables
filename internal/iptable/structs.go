package iptable

type IPTable struct {
	name   string
	chains []*IPChain
}

func CreateIpTable(name string) *IPTable {
	return &IPTable{name: name}
}

func (t *IPTable) AddChain(name, defaultAction string) *IPChain {
	chain := &IPChain{
		name:          name,
		defaultAction: defaultAction,
	}
	t.chains = append(t.chains, chain)
	return chain
}

type IPChain struct {
	name, defaultAction string
	rules               []*IPRule
}

type IPRule struct {
	comment, protocol         string
	source, destination       string
	inInterface, outInterface string

	// This specifies the target of the rule; i.e., what to do if the packet matches it.
	// The target can be a user-defined chain (other than the one this rule is in),
	// one of the special builtin targets which decide the fate of the packet immediately,
	// or an extension (see EXTENSIONS below).
	// If this option is omitted in a rule (and -g is not used),
	// then matching the rule will have no effect on the packet's fate,
	// but the counters on the rule will be incremented.
	jumpTarget *IPChain

	// This specifies that the processing should continue in a user specified chain.
	// Unlike the --jump option return will not continue processing in this chain but instead in the chain that called us via --jump.
	gotoTarget *IPChain
}

func (c *IPChain) AddRuleFromImports(currentTable *IPTable, cmdArgs *IpTablesCmdArgs) *IPRule {
	rule := &IPRule{
		comment:      cmdArgs.GetFlagValueByName("", "--comment"),
		protocol:     cmdArgs.GetFlagValueByName("-p", "--protocol"),
		source:       cmdArgs.GetFlagValueByName("-s", "--source"),
		destination:  cmdArgs.GetFlagValueByName("-d", "--destination"),
		inInterface:  cmdArgs.GetFlagValueByName("-i", "--in-interface"),
		outInterface: cmdArgs.GetFlagValueByName("-o", "--out-interface"),
		jumpTarget:   currentTable.FindChainByName(cmdArgs.GetFlagValueByName("-j", "--jump")),
		gotoTarget:   currentTable.FindChainByName(cmdArgs.GetFlagValueByName("-g", "--goto")),
	}
	c.rules = append(c.rules, rule)
	return rule
}

func (t *IPTable) FindChainByName(name string) *IPChain {
	for _, chain := range t.chains {
		if chain.name == name {
			return chain
		}
	}
	return nil
}
