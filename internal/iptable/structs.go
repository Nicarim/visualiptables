package iptable

import (
	"fmt"
	"github.com/silas/dag"
	"golang.org/x/exp/slices"
	"strings"
)

// See https://linux.die.net/man/8/iptables
// Target Extensions
var specialTargets = []string{
	"balance",
	"classify",
	"clusterip",
	"connmark",
	"dnat",
	"dscp",
	"ecn",
	"ipmark",
	"ipv4optsstrip",
	"log",
	"mark",
	"masquerade",
	"mirror",
	"netmap",
	"nfqueue",
	"notrack",
	"redirect",
	"reject",
	"same",
	"set",
	"snat",
	"tarpit",
	"tcpmss",
	"tos",
	"trace",
	"ttl",
	"ulog",
	"xor",
}

type IPTable struct {
	name   string
	chains []*IPChain
}

func (t *IPTable) Name() string {
	return t.name
}

func CreateIpTable(name string) *IPTable {
	return &IPTable{name: name}
}

func (t *IPTable) AddChain(name, defaultAction string, table *IPTable) *IPChain {
	chain := &IPChain{
		name:          name,
		defaultAction: defaultAction,
		table:         table,
	}
	t.chains = append(t.chains, chain)
	return chain
}

type IPChain struct {
	name, defaultAction string
	special             bool //Indicates if it is an extension chain
	table               *IPTable
	rules               []*IPRule
}

type IPRule struct {
	comment, protocol         string
	source, destination       string
	inInterface, outInterface string
	chain                     *IPChain

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

func (r *IPRule) InInterface() string {
	if r.inInterface == "" {
		return "any"
	}
	return r.inInterface
}

func (r *IPRule) OutInterface() string {
	if r.outInterface == "" {
		return "any"
	}
	return r.outInterface
}

func (r *IPRule) JumpTarget() *IPChain {
	return r.jumpTarget
}

func (r *IPRule) Name() string {
	str := "IPRule"
	str += fmt.Sprintf(" table: %s, chain: %s", r.chain.table.name, r.chain.name)
	if r.jumpTarget != nil {
		if r.jumpTarget.special {
			str += fmt.Sprintf("|Extension Target: %s", r.jumpTarget.name)
		} else {
			str += fmt.Sprintf("|Next chain: %s", r.jumpTarget.name)
		}
	} else {
		str += fmt.Sprintf("|Stay within chain: %s", r.chain.name)
	}
	return str
}

func (r *IPRule) DotNode(name string, opts *dag.DotOpts) *dag.DotNode {
	return &dag.DotNode{
		Name: name,
		Attrs: map[string]string{
			"fillcolor": "beige",
			"style":     "filled",
			"shape":     "record",
			"label":     "⇒" + r.InInterface() + "|" + name + "|" + r.OutInterface() + "⇒",
		},
	}
}

func (c *IPChain) Rules() []*IPRule {
	return c.rules
}

func (c *IPChain) AddRuleFromImports(currentTable *IPTable, cmdArgs *IpTablesCmdArgs) *IPRule {
	jumpName := cmdArgs.GetFlagValueByName("-j", "--jump")
	var jumpTarget *IPChain
	if slices.Contains(specialTargets, strings.ToLower(jumpName)) {
		jumpTarget = &IPChain{
			name:          jumpName,
			defaultAction: "-",
			special:       true,
			table:         nil,
			rules:         nil,
		}
	} else {
		jumpTarget = currentTable.FindChainByName(jumpName)
	}
	rule := &IPRule{
		chain:        c,
		comment:      cmdArgs.GetFlagValueByName("", "--comment"),
		protocol:     cmdArgs.GetFlagValueByName("-p", "--protocol"),
		source:       cmdArgs.GetFlagValueByName("-s", "--source"),
		destination:  cmdArgs.GetFlagValueByName("-d", "--destination"),
		inInterface:  cmdArgs.GetFlagValueByName("-i", "--in-interface"),
		outInterface: cmdArgs.GetFlagValueByName("-o", "--out-interface"),
		jumpTarget:   jumpTarget,
		gotoTarget:   currentTable.FindChainByName(cmdArgs.GetFlagValueByName("-g", "--goto")),
	}
	c.rules = append(c.rules, rule)
	return rule
}

func (c *IPChain) String() string {
	return fmt.Sprintf("table: %s, chain: %s", c.table.name, c.name)
}

func (c *IPChain) Name() string {
	return c.String()
}

func (t *IPTable) FindChainByName(name string) *IPChain {
	for _, chain := range t.chains {
		if strings.ToLower(chain.name) == strings.ToLower(name) {
			return chain
		}
	}
	return nil
}
