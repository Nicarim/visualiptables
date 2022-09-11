package simulator

import (
	"fmt"
	"github.com/silas/dag"
	"strings"
	"visualiptables/internal/iptable"
)

// device_ut = device under test.
// Simulated device which is the receiver, sender, or processor of the packet that is being sent
// It may contain internet interfaces, and contains all the iptable tables, chains and rules.

type PacketOrigin int

const (
	OriginOutside PacketOrigin = iota
	OriginForward
	OriginInside
)

type ProcessingPath struct {
	table    *iptable.IPTable
	chain    *iptable.IPChain
	pathType string
}

// This defines built-in routing as defined in
// https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
// Used as a blueprint for defining routing in actual config through DAG
// We only follow network layer path for now
var tableOrder = map[string][]string{
	"prerouting": {
		"raw",
		"mangle",
		"nat",
	},
	"input": {
		"mangle",
		"nat",
		"filter",
	},
	"forward": {
		"mangle",
		"filter",
	},
	"output": {
		"raw",
		"mangle",
		"nat",
		"filter",
	},
	"postrouting": {
		"mangle",
		"nat",
	},
}

var chainOrder = map[PacketOrigin][]string{
	OriginInside: {
		"prerouting",
		"input",
	},
	OriginForward: {
		"prerouting",
		"forward",
		"postrouting",
	},
	OriginOutside: {
		"output",
		"postrouting",
	},
}

type DeviceUnderTest struct {
	interfaces []string
	Tables     []*iptable.IPTable
}

func (t *DeviceUnderTest) findTableByName(name string) *iptable.IPTable {
	for _, t := range t.Tables {
		if strings.ToLower(t.Name()) == name {
			return t
		}
	}
	return nil
}

func (t *DeviceUnderTest) AddInterface(name string) {
	t.interfaces = append(t.interfaces, name)
}

func (t *DeviceUnderTest) getDefaultFlow(origin PacketOrigin) []*iptable.IPChain {
	var orderedChains []*iptable.IPChain
	for _, chainName := range chainOrder[origin] {
		for _, tableName := range tableOrder[chainName] {
			table := t.findTableByName(tableName)
			if table == nil {
				continue
			}
			chain := table.FindChainByName(chainName)
			if chain == nil {
				continue
			}
			orderedChains = append(orderedChains, chain)
		}
	}
	return orderedChains
}

type IPRuleSubgraph struct {
	VertexName   string
	AcyclicGraph *dag.AcyclicGraph
}

func (s *IPRuleSubgraph) Name() string {
	return s.VertexName
}

func (s *IPRuleSubgraph) Subgraph() dag.Grapher {
	return s.AcyclicGraph
}

func (s *IPRuleSubgraph) DotNode(name string, opts *dag.DotOpts) *dag.DotNode {
	return &dag.DotNode{
		Name: name,
		Attrs: map[string]string{
			"style":     "filled",
			"fillcolor": "beige",
		},
	}
}

func (t *DeviceUnderTest) SimulatePacket(origin PacketOrigin) {
	// let's assume we're trying to send ICMP packet one way, without reply

	chains := t.getDefaultFlow(origin)
	g := &dag.AcyclicGraph{}
	for i, chain := range chains {
		g.Add(chain)
		if i > 0 {
			previousChain := chains[i-1]
			rules := previousChain.Rules()
			gi := &dag.AcyclicGraph{}
			for j, rule := range rules {
				gi.Add(rule)
				jumpTarget := rule.JumpTarget()
				if jumpTarget != nil {
					gi.Add(jumpTarget)
					gi.Connect(dag.BasicEdge(rule, jumpTarget))
					targetRules := jumpTarget.Rules()
					if len(targetRules) > 0 {
						for h, targetRule := range targetRules {
							gi.Add(targetRule)
							if h > 0 {
								gi.Connect(dag.BasicEdge(targetRules[h-1], targetRule))
							}
						}
						gi.Connect(dag.BasicEdge(jumpTarget, targetRules[0]))
					}
				}
				if j > 0 {
					gi.Connect(dag.BasicEdge(rules[j-1], rule))
				}
			}
			if len(rules) == 0 {
				g.Connect(dag.BasicEdge(previousChain, chain))
			} else {
				subGraph := g.Add(&IPRuleSubgraph{
					VertexName:   fmt.Sprintf("rules of %s", previousChain.Name()),
					AcyclicGraph: gi,
				})
				g.Connect(dag.BasicEdge(previousChain, subGraph))
				g.Connect(dag.BasicEdge(subGraph, chain))
			}
		}
	}
	dot := g.Dot(&dag.DotOpts{
		Verbose:    true,
		DrawCycles: false,
		MaxDepth:   -1,
	})
	fmt.Println(string(dot))
}
