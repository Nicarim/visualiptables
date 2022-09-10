package iptable

import "strings"

type IpTablesCmdArgs struct {
	args []*IptablesCmdArg
}

type IptablesCmdArg struct {
	Flag, Value string
}

type IptablesCmdParserState int

const (
	OptionStart IptablesCmdParserState = iota
	CmdValue
	CmdValueQuoted
	CmdFinished
	CmdFinishedLast
)

// FindFlagByName
// either shortForm or longForm may be omitted, if it is not available in iptables
func (args *IpTablesCmdArgs) FindFlagByName(shortForm, longForm string) *IptablesCmdArg {
	for _, arg := range args.args {
		if arg.Flag == shortForm || arg.Flag == longForm {
			return arg
		}
	}
	return nil
}

func (args *IpTablesCmdArgs) GetFlagValueByName(shortForm, longForm string) string {
	flag := args.FindFlagByName(shortForm, longForm)
	if flag == nil {
		return ""
	}
	return flag.Value
}

func ParseIpTablesCmdString(line string) IpTablesCmdArgs {
	var cmdArgs IpTablesCmdArgs
	state := OptionStart
	words := strings.Fields(line)
	flag := ""
	value := ""
	totalLen := len(words)
	for i, word := range words {
	BACKTRACK:
		switch state {
		case OptionStart:
			value = ""
			if word[0] == '-' {
				flag = word
			}
			if i == (totalLen - 1) {
				state = CmdFinishedLast
				goto BACKTRACK
			}
			state = CmdValue
		case CmdValue:
			if word[0] == '-' {
				state = CmdFinished
				goto BACKTRACK
			}
			if value == "" {
				value = word
			} else {
				value = value + " " + word
			}
			if word[0] == '"' {
				if word[len(word)-1] == '"' {
					state = CmdFinished
					goto BACKTRACK
				} else {
					state = CmdValueQuoted
				}
			}
			if i == (totalLen - 1) {
				state = CmdFinished
				goto BACKTRACK
			}
		case CmdValueQuoted:
			value = value + " " + word
			if word[len(word)-1] == '"' {
				state = CmdFinished
				goto BACKTRACK
			}
		case CmdFinishedLast:
			fallthrough
		case CmdFinished:
			if value == "" {
				value = "true" // means a boolean flag is set
			}
			cmdArgs.args = append(cmdArgs.args, &IptablesCmdArg{
				Flag:  flag,
				Value: value,
			})
			if state == CmdFinishedLast {
				break
			}
			state = OptionStart
			if word[0] == '-' {
				goto BACKTRACK
			}
		}
	}
	return cmdArgs
}
