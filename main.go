package main

import (
	"FilterParser/parser"
	"fmt"
)

type FilterTest struct {
	Expression string
	ExpectedDownlinkResult string
	ExpectedUplinkResult string
}

var (
	tests = []FilterTest {
		{
			Expression:     "srv.ip == 1.2.3.4",
			ExpectedDownlinkResult: "-S 1.2.3.4",
			ExpectedUplinkResult: "-D 1.2.3.4",
		},
		{
			Expression:     "cli.ip == 5.6.7.8",
			ExpectedDownlinkResult: "-D 5.6.7.8",
			ExpectedUplinkResult: "-S 5.6.7.8",
		},
		{
			Expression:             "srv.ip == 1.2.3.4 AND srv.tcp.port == 8080",
			ExpectedDownlinkResult: "-S 1.2.3.4 -p tcp --sport 8080",
			ExpectedUplinkResult:   "-D 1.2.3.4 -p tcp --dport 8080",
		},
		{
			Expression:             "cli.ip == 5.6.7.0/24 AND srv.tcp.port == 80 AND NOT ip.dscp == 30",
			ExpectedDownlinkResult: "-D 5.6.7.0/24 -p tcp --sport 80 -m dscp ! --dscp 30",
			ExpectedUplinkResult:   "-S 5.6.7.0/24 -p tcp --dport 80 -m dscp ! --dscp 30",
		},
	}
)
func main() {

	for idx, test := range(tests){
		fmt.Printf("Expression %d: %s\n", idx, test.Expression)
		p := parser.FilterParser{}
		filterTree := p.Parse(test.Expression)
		fmt.Printf("Uplink Filters\n")
		for filterIdx, filter := range(filterTree.ULFilters) {
			fmt.Printf("%d: %s\n", filterIdx, filter)
		}
		fmt.Printf("Downlink Filters\n")
		for filterIdx, filter := range(filterTree.DLFilters) {
			fmt.Printf("%d: %s\n", filterIdx, filter)
		}
		fmt.Printf("\n\n")
	}
}
