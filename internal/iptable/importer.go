package iptable

import (
	"fmt"
	"strings"
)

var Tables []*IPTable
var currentTable *IPTable

func ParseImportIpTables(line string) {
	if line[0] == '*' {
		currentTable = CreateIpTable(line[1:])
		Tables = append(Tables, currentTable)
	}
	if line[0] == ':' {
		words := strings.Fields(line)
		currentTable.AddChain(words[0][1:], words[1])
	}
	if line[:2] == "-A" {
		cmdArgs := ParseIpTablesCmdString(line)
		appendedChainName := cmdArgs.FindFlagByName("-A", "")
		if appendedChainName == nil {
			fmt.Println("WARNING: this line doesn't contain chain, invalid line")
			return
		}
		chainToAppend := currentTable.FindChainByName(appendedChainName.Value)
		if chainToAppend == nil {
			fmt.Printf("WARNING: chane named %s doesn't exist \n", appendedChainName.Value)
		}

		chainToAppend.AddRuleFromImports(currentTable, &cmdArgs)
	}
}
