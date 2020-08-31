package main

import (
	"fmt"
	"github.com/BGrewell/FilterExpressionParser/parser"
)

type FilterTest struct {
	Expression             string
	ExpectedDownlinkResult []string
	ExpectedUplinkResult   []string
}

var (
	tests = []FilterTest{
		{
			// 0
			Expression:             "srv.ip == 1.2.3.4",
			ExpectedDownlinkResult: []string{"-s 1.2.3.4"},
			ExpectedUplinkResult:   []string{"-d 1.2.3.4"},
		},
		{
			// 1
			Expression:             "cli.ip == 5.6.7.8",
			ExpectedDownlinkResult: []string{"-d 5.6.7.8"},
			ExpectedUplinkResult:   []string{"-s 5.6.7.8"},
		},
		{
			// 2
			Expression:             "srv.ip == 1.2.3.4 AND srv.tcp.port == 8080",
			ExpectedDownlinkResult: []string{"-s 1.2.3.4 -p tcp --sport 8080"},
			ExpectedUplinkResult:   []string{"-d 1.2.3.4 -p tcp --dport 8080"},
		},
		{
			// 3
			Expression:             "cli.ip == 5.6.7.0/24 AND srv.tcp.port == 80 AND NOT ip.dscp == 30",
			ExpectedDownlinkResult: []string{"-d 5.6.7.0/24 -p tcp --sport 80 -m dscp ! --dscp 30"},
			ExpectedUplinkResult:   []string{"-s 5.6.7.0/24 -p tcp --dport 80 -m dscp ! --dscp 30"},
		},
		{
			// 4
			Expression: "srv.ip == 1.2.3.4 OR srv.ip == 5.6.7.8 AND srv.tcp.port == 80 OR srv.tcp.port == 443",
			ExpectedDownlinkResult: []string{"-s 1.2.3.4 -p tcp --sport 80",
				"-s 5.6.7.8 -p tcp --sport 80",
				"-s 1.2.3.4 -p tcp --sport 443",
				"-s 5.6.7.8 -p tcp --sport 443"},
			ExpectedUplinkResult: []string{"-d 1.2.3.4 -p tcp --dport 80",
				"-d 5.6.7.8 -p tcp --dport 80",
				"-d 1.2.3.4 -p tcp --dport 443",
				"-d 5.6.7.8 -p tcp --dport 443"},
		},
		{
			// 5
			Expression:             "conn.bytes == 0:1000",
			ExpectedDownlinkResult: []string{"-m connbytes --connbytes-dir original --connbytes-mode bytes --connbytes 0:1000"},
			ExpectedUplinkResult:   []string{"-m connbytes --connbytes-dir original --connbytes-mode bytes --connbytes 0:1000"},
		},
		{
			// 6
			Expression:             "conn.packets == 0:1000",
			ExpectedDownlinkResult: []string{"-m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:1000"},
			ExpectedUplinkResult:   []string{"-m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:1000"},
		},
	}
)

func FilterInExpectedSet(filter string, expected []string) (found bool) {
	for _, expect := range expected {
		if filter == expect {
			return true
		}
	}
	return false
}

func main() {

	fmt.Printf("%-20s %-20s %-20s %s\n", "TestID", "ULResult", "DLResult", "Reason")
	for idx, test := range tests {
		p := parser.FilterParser{}
		filterTree, err := p.Parse(test.Expression)
		ulPassed := "PASSED"
		dlPassed := "PASSED"
		for _, filter := range filterTree.ULFilters {
			if !FilterInExpectedSet(filter, test.ExpectedUplinkResult) {
				ulPassed = "FAILED"
				break
			}
		}
		for _, filter := range filterTree.DLFilters {
			if !FilterInExpectedSet(filter, test.ExpectedDownlinkResult) {
				dlPassed = "FAILED"
				break
			}
		}
		if err != nil {
			ulPassed = "FAILED"
			dlPassed = "FAILED"
		}
		fmt.Printf("%-20d %-20s %-20s %v\n", idx, ulPassed, dlPassed, err)
	}
}
