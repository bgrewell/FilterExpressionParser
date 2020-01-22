package main

import (
	"FilterParser/parser"
	"fmt"
)

type FilterTest struct {
	Expression             string
	ExpectedDownlinkResult []string
	ExpectedUplinkResult   []string
}

var (
	tests = []FilterTest{
		{
			Expression:             "srv.ip == 1.2.3.4",
			ExpectedDownlinkResult: []string{"-s 1.2.3.4"},
			ExpectedUplinkResult:   []string{"-d 1.2.3.4"},
		},
		{
			Expression:             "cli.ip == 5.6.7.8",
			ExpectedDownlinkResult: []string{"-d 5.6.7.8"},
			ExpectedUplinkResult:   []string{"-s 5.6.7.8"},
		},
		{
			Expression:             "srv.ip == 1.2.3.4 AND srv.tcp.port == 8080",
			ExpectedDownlinkResult: []string{"-s 1.2.3.4 -p tcp --sport 8080"},
			ExpectedUplinkResult:   []string{"-d 1.2.3.4 -p tcp --dport 8080"},
		},
		{
			Expression:             "cli.ip == 5.6.7.0/24 AND srv.tcp.port == 80 AND NOT ip.dscp == 30",
			ExpectedDownlinkResult: []string{"-d 5.6.7.0/24 -p tcp --sport 80 -m dscp ! --dscp 30"},
			ExpectedUplinkResult:   []string{"-s 5.6.7.0/24 -p tcp --dport 80 -m dscp ! --dscp 30"},
		},
		{
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
	}
)

func FilterInExpectedSet(filter string, expected []string) (found bool) {
	for _, expect := range(expected) {
		if filter == expect {
			return true
		}
	}
	return false
}

func main() {

	fmt.Printf("%-20s %-20s %-20s\n", "TestID", "ULResult", "DLResult")
	for idx, test := range tests {
		p := parser.FilterParser{}
		filterTree := p.Parse(test.Expression)
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
		fmt.Printf("%-20d %-20s %-20s\n", idx, ulPassed, dlPassed)
	}
}
