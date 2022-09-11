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
			"fillcolor": "brown1",
		},
	}
}

func rulesProcessor(ch *iptable.IPChain, depth int) *IPRuleSubgraph {
	rules := ch.Rules()
	gi := &dag.AcyclicGraph{}
	for j, rule := range rules {
		gi.Add(rule)
		jumpTarget := rule.JumpTarget()
		if jumpTarget != nil {
			gi = chainsProcessor(gi, []*iptable.IPChain{jumpTarget}, depth+1)
		}
		if j > 0 {
			gi.Connect(dag.BasicEdge(rules[j-1], rule))
		}
	}
	return &IPRuleSubgraph{
		VertexName:   fmt.Sprintf("rules of %s", ch.Name()),
		AcyclicGraph: gi,
	}
}

func chainsProcessor(g *dag.AcyclicGraph, chains []*iptable.IPChain, depth int) *dag.AcyclicGraph {
	var previousVertex dag.Vertex
	for i, chain := range chains {
		g.Add(chain)
		rulesCount := len(chain.Rules())
		if rulesCount > 0 {
			rulesDag := rulesProcessor(chain, depth)
			g.Add(rulesDag)
			if i > 0 {
				g.Connect(dag.BasicEdge(previousVertex, chain))
				g.Connect(dag.BasicEdge(chain, rulesDag))
			} else {
				g.Connect(dag.BasicEdge(chain, rulesDag))
			}
			previousVertex = rulesDag
		} else {
			if i > 0 {
				g.Connect(dag.BasicEdge(previousVertex, chain))
			}
			previousVertex = chain
		}
	}
	return g
}

func (t *DeviceUnderTest) GenerateDag(origin PacketOrigin) *dag.AcyclicGraph {
	chains := t.getDefaultFlow(origin)
	g := &dag.AcyclicGraph{}
	return chainsProcessor(g, chains, 0)
}

func (t *DeviceUnderTest) SimulatePacket(origin PacketOrigin) {
	// let's assume we're trying to send ICMP packet one way, without reply
	g := t.GenerateDag(origin)
	dot := g.Dot(&dag.DotOpts{
		Verbose:    true,
		DrawCycles: false,
		MaxDepth:   -1,
	})
	fmt.Println(string(dot))
}
