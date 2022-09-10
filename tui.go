package main

//import "github.com/rivo/tview"
//
//func createTui() {
//	app := tview.NewApplication()
//
//	ipPacket := SentIPPacket{
//		packetType: "ICMP",
//		sentFrom:   "Outside",
//	}
//	packetBox := ipPacket.getGridView()
//
//	flowBox := tview.NewBox().SetBorder(true).SetTitle("Bottom flow view")
//
//	flex := tview.NewFlex().SetDirection(tview.FlexRow).
//		AddItem(packetBox, 0, 1, false).
//		AddItem(flowBox, 0, 3, false)
//
//	if err := app.SetRoot(flex, true).SetFocus(flex).Run(); err != nil {
//		panic(err)
//	}
//
//}
