package main

import (
	"bufio"
	"fmt"
	"os"
	"visualiptables/internal/iptable"
	"visualiptables/internal/simulator"
)

func main() {
	readFile, err := os.Open("example_own.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		iptable.ParseImportIpTables(fileScanner.Text())
	}
	dut := simulator.DeviceUnderTest{
		Tables: iptable.Tables,
	}
	dut.SimulatePacket(simulator.OriginForward)

	err = readFile.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	//createTui()

}
