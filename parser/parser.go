package parser

import (
	"fmt"
	"log"
	"math"
	"strings"
)

type IPTablesFilters struct {
	ULFilters []string
	DLFilters []string
}

type FilterNode interface {
	Eval() IPTablesFilters
}

type AND struct {
	Left FilterNode
	Right FilterNode
}

func (obj AND) Eval() IPTablesFilters {
	filtersLeft := obj.Left.Eval()
	filtersRight := obj.Right.Eval()
	outputFilters := IPTablesFilters{}
	for _, ulFilterLeft := range(filtersLeft.ULFilters) {
		for _, ulFilterRight := range(filtersRight.ULFilters) {
			outputFilters.ULFilters = append(outputFilters.ULFilters, strings.Join([]string{ulFilterLeft, ulFilterRight}, " "))
		}
	}
	for _, dlFilterLeft := range(filtersLeft.DLFilters) {
		for _, dlFilterRight := range(filtersRight.DLFilters) {
			outputFilters.DLFilters = append(outputFilters.DLFilters, strings.Join([]string{dlFilterLeft, dlFilterRight}, " "))
		}
	}
	return outputFilters
}

type OR struct {
	Left FilterNode
	Right FilterNode
}

func (obj OR) Eval() IPTablesFilters {
	filtersLeft := obj.Left.Eval()
	filtersRight := obj.Right.Eval()
	filtersLeft.ULFilters = append(filtersLeft.ULFilters, filtersRight.ULFilters...)
	filtersLeft.DLFilters = append(filtersLeft.DLFilters, filtersRight.DLFilters...)
	return filtersLeft
}

type NOT struct {
	Item FilterNode
}

func (obj NOT) Eval() IPTablesFilters {
	//TODO: This is naive but just assume we want to negate the furthest right parameter
	filters := obj.Item.Eval()
	for idx, filter := range(filters.ULFilters) {
		insertionPoint := strings.LastIndex(filter, " -")
		filters.ULFilters[idx] = fmt.Sprintf("%s !%s", filter[:insertionPoint], filter[insertionPoint:])
	}
	for idx, filter := range(filters.DLFilters) {
		insertionPoint := strings.LastIndex(filter, " -")
		filters.DLFilters[idx] = fmt.Sprintf("%s !%s", filter[:insertionPoint], filter[insertionPoint:])
	}
	return filters
}

type EQ struct {
	Key string
	Value string
}

// Leaf nodes. In this case all leafs are always equals, never OR, AND, NOT
func (obj EQ) Eval() IPTablesFilters {
	filters := IPTablesFilters{}
	ulFilter := ""
	dlFilter := ""
	switch strings.ToLower(obj.Key) {
	case "srv.ip":
		ulFilter = fmt.Sprintf("-d %s", obj.Value)
		dlFilter = fmt.Sprintf("-s %s", obj.Value)
	case "cli.ip":
		ulFilter = fmt.Sprintf("-s %s", obj.Value)
		dlFilter = fmt.Sprintf("-d %s", obj.Value)
	case "srv.tcp.port":
		ulFilter = fmt.Sprintf("-p tcp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p tcp --sport %s", obj.Value)
	case "cli.tcp.port":
		ulFilter = fmt.Sprintf("-p tcp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p tcp --dport %s", obj.Value)
	case "srv.udp.port":
		ulFilter = fmt.Sprintf("-p udp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p udp --sport %s", obj.Value)
	case "cli.udp.port":
		ulFilter = fmt.Sprintf("-p udp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p udp --dport %s", obj.Value)
	case "srv.icmp.port":
		ulFilter = fmt.Sprintf("-p icmp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p icmp --sport %s", obj.Value)
	case "cli.icmp.port":
		ulFilter = fmt.Sprintf("-p icmp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p icmp --dport %s", obj.Value)
	case "proto.icmp":
		ulFilter = fmt.Sprint("-p icmp")
		dlFilter = fmt.Sprint("-p icmp")
	case "proto.tcp":
		ulFilter = fmt.Sprint("-p tcp")
		dlFilter = fmt.Sprint("-p tcp")
	case "proto.udp":
		ulFilter = fmt.Sprint("-p udp")
		dlFilter = fmt.Sprint("-p udp")
	case "ip.dscp":
		ulFilter = fmt.Sprintf("-m dscp --dscp %s", obj.Value)
		dlFilter = fmt.Sprintf("-m dscp --dscp %s", obj.Value)
	}
	filters.ULFilters = []string{ulFilter}
	filters.DLFilters = []string{dlFilter}
	return filters
}

type FilterParser struct {
	InputExpression string
}

func (fp *FilterParser) Parse(expression string) (filterTree IPTablesFilters)  {
	//TODO: There are a lot of issues with how this handles parsing. Need to make it follow common rules when handling
	// parsing binary trees

	// convert the string to all lower case
	expression = strings.ToLower(expression)
	filterParser := SplitExpression(expression)
	return filterParser.Eval()
}

func SplitExpression(expression string) FilterNode {
	// Get a count of the 'and' and 'or' operators. We don't care about 'not' and 'eq' here
	totalNonLeafOperators := strings.Count(expression, " and ") + strings.Count(expression, " or ")
	if totalNonLeafOperators > 0 {
		// Continue to break down
		center := int(math.Floor(float64(totalNonLeafOperators / 2)))
		if center == 0 { center = 1}
		operator := "and"
		marker := 0
		location := 0
		for i := 0; i < center; i++ {
			nextAnd := strings.Index(expression[marker:], " and ")
			nextOr := strings.Index(expression[marker:], " or ")
			if (nextOr != -1) && (nextAnd == -1 || nextOr < nextAnd) {
				location = nextOr
				operator = "or"
			} else if (nextAnd != -1) && (nextOr == -1 || nextAnd < nextOr) {
				location = nextAnd
				operator = "and"
			} else {
				log.Fatal("Oops, failed to parse string")
			}
		}
		fmt.Printf("location: %d\n", location)
		if operator == "and" {
			fmt.Printf("AND left: %s\n", expression[:location])
			fmt.Printf("AND Right: %s\n", expression[location+5:])
			return AND{
				SplitExpression(expression[:location]),
				SplitExpression(expression[location+5:]),
			}
		} else if operator == "or" {
			fmt.Printf("OR left: %s\n", expression[:location])
			fmt.Printf("OR Right: %s\n", expression[location+4:])
			return OR{
				SplitExpression(expression[:location]),
				SplitExpression(expression[location+4:]),
			}
		}

	} else {
		parts := strings.Split(expression, "==")
		fmt.Printf("parts: [%s|%s]\n", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		return EQ{
			Key: parts[0],
			Value: parts[1],
		}
	}

	return EQ{
		"ERROR",
		"ERROR",
	}
}