package parser

import (
	"fmt"
	"log"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type IPTablesFilters struct {
	ULFilters []string `json:"ul_filters"`
	DLFilters []string `json:"dl_filters"`
}

type FilterNode interface {
	Eval() IPTablesFilters
}

type AND struct {
	Left  FilterNode `json:"left_node"`
	Right FilterNode `json:"right_node"`
}

func (obj AND) Eval() IPTablesFilters {
	filtersLeft := obj.Left.Eval()
	filtersRight := obj.Right.Eval()
	outputFilters := IPTablesFilters{}
	for _, ulFilterLeft := range filtersLeft.ULFilters {
		for _, ulFilterRight := range filtersRight.ULFilters {
			filter := strings.Join([]string{ulFilterLeft, ulFilterRight}, " ")
			cleaned_filter := strings.ReplaceAll(filter, "  ", " ") // Hacky way to remove double spaces that are showing up in some strings for an unknown reason
			outputFilters.ULFilters = append(outputFilters.ULFilters, cleaned_filter)
		}
	}
	for _, dlFilterLeft := range filtersLeft.DLFilters {
		for _, dlFilterRight := range filtersRight.DLFilters {
			filter := strings.Join([]string{dlFilterLeft, dlFilterRight}, " ")
			cleaned_filter := strings.ReplaceAll(filter, "  ", " ") // Hacky way to remove double spaces that are showing up in some strings for an unknown reason
			outputFilters.DLFilters = append(outputFilters.DLFilters, cleaned_filter)
		}
	}
	return outputFilters
}

type OR struct {
	Left  FilterNode `json:"left_node"`
	Right FilterNode `json:"right_node"`
}

func (obj OR) Eval() IPTablesFilters {
	filtersLeft := obj.Left.Eval()
	filtersRight := obj.Right.Eval()
	filtersLeft.ULFilters = append(filtersLeft.ULFilters, filtersRight.ULFilters...)
	filtersLeft.DLFilters = append(filtersLeft.DLFilters, filtersRight.DLFilters...)
	return filtersLeft
}

type NOT struct {
	Item FilterNode `json:"item"`
}

func (obj NOT) Eval() IPTablesFilters {
	//TODO: This is naive but just assume we want to negate the furthest right parameter
	filters := obj.Item.Eval()
	for idx, filter := range filters.ULFilters {
		insertionPoint := strings.LastIndex(filter, " -")
		filters.ULFilters[idx] = fmt.Sprintf("%s !%s", filter[:insertionPoint], filter[insertionPoint:])
	}
	for idx, filter := range filters.DLFilters {
		insertionPoint := strings.LastIndex(filter, " -")
		filters.DLFilters[idx] = fmt.Sprintf("%s !%s", filter[:insertionPoint], filter[insertionPoint:])
	}
	return filters
}

type EQ struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Leaf nodes. In this case all leafs are always equals, never OR, AND, NOT
func (obj EQ) Eval() IPTablesFilters {
	filters := IPTablesFilters{}
	ulFilter := ""
	dlFilter := ""
	switch strings.ToLower(obj.Key) {
	case "srv.ip":
		validateIPAddress(obj.Value)
		ulFilter = fmt.Sprintf("-d %s", obj.Value)
		dlFilter = fmt.Sprintf("-s %s", obj.Value)
	case "cli.ip":
		validateIPAddress(obj.Value)
		ulFilter = fmt.Sprintf("-s %s", obj.Value)
		dlFilter = fmt.Sprintf("-d %s", obj.Value)
	case "srv.tcp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p tcp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p tcp --sport %s", obj.Value)
	case "cli.tcp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p tcp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p tcp --dport %s", obj.Value)
	case "srv.udp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p udp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p udp --sport %s", obj.Value)
	case "cli.udp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p udp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p udp --dport %s", obj.Value)
	case "srv.icmp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p icmp --dport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p icmp --sport %s", obj.Value)
	case "cli.icmp.port":
		validatePortNumber(obj.Value)
		ulFilter = fmt.Sprintf("-p icmp --sport %s", obj.Value)
		dlFilter = fmt.Sprintf("-p icmp --dport %s", obj.Value)
	case "proto.icmp":
		validateEmptyValue(obj.Key, obj.Value)
		ulFilter = fmt.Sprint("-p icmp")
		dlFilter = fmt.Sprint("-p icmp")
	case "proto.tcp":
		validateEmptyValue(obj.Key, obj.Value)
		ulFilter = fmt.Sprint("-p tcp")
		dlFilter = fmt.Sprint("-p tcp")
	case "proto.udp":
		validateEmptyValue(obj.Key, obj.Value)
		ulFilter = fmt.Sprint("-p udp")
		dlFilter = fmt.Sprint("-p udp")
	case "ip.dscp":
		validateDSCPValue(obj.Value)
		ulFilter = fmt.Sprintf("-m dscp --dscp %s", obj.Value)
		dlFilter = fmt.Sprintf("-m dscp --dscp %s", obj.Value)
	default:
		log.Fatalf("Unrecognized field: %s", obj.Key)
	}
	filters.ULFilters = []string{ulFilter}
	filters.DLFilters = []string{dlFilter}
	return filters
}

type FilterParser struct {
}

func (fp *FilterParser) Parse(expression string) (filterTree IPTablesFilters) {
	//TODO: There are a lot of issues with how this handles parsing. Need to make it follow common rules when handling
	// parsing binary trees

	// convert the string to all lower case
	expression = strings.ToLower(expression)
	filterParser := SplitExpression(expression)
	filterTree = filterParser.Eval()
	return filterTree
}

func SplitExpression(expression string) FilterNode {
	// Get a count of the 'and' and 'or' operators. We don't care about 'not' and 'eq' here
	totalNonLeafOperators := strings.Count(expression, " and ") + strings.Count(expression, " or ")
	if totalNonLeafOperators > 0 {
		// Continue to break down
		center := int(math.Ceil(float64(totalNonLeafOperators) / 2))
		if center == 0 {
			center = 1
		}
		operator := "and"
		marker := 0
		location := 0
		for i := 0; i < center; i++ {
			nextAnd := strings.Index(expression[marker:], " and ")
			nextOr := strings.Index(expression[marker:], " or ")
			if (nextOr != -1) && (nextAnd == -1 || nextOr < nextAnd) {
				location = nextOr
				marker = nextOr + 4
				operator = "or"
			} else if (nextAnd != -1) && (nextOr == -1 || nextAnd < nextOr) {
				location = nextAnd
				marker = nextAnd + 5
				operator = "and"
			} else {
				log.Fatal("Oops, failed to parse string")
			}
		}
		if operator == "and" {
			return AND{
				SplitExpression(expression[:location]),
				SplitExpression(expression[location+5:]),
			}
		} else if operator == "or" {
			return OR{
				SplitExpression(expression[:location]),
				SplitExpression(expression[location+4:]),
			}
		}

	} else {
		negate := strings.Contains(expression, "not")
		parts := strings.Split(expression, "==")
		parts[0] = strings.TrimSpace(parts[0])
		parts[1] = strings.TrimSpace(parts[1])
		if negate {
			parts[0] = strings.TrimSpace(strings.Replace(parts[0], "not", "", 1))
			return NOT{
				EQ{
					Key:   parts[0],
					Value: parts[1],
				},
			}
		} else {
			return EQ{
				Key:   parts[0],
				Value: parts[1],
			}
		}
	}

	return EQ{
		"ERROR",
		"ERROR",
	}
}

func validateIPAddress(ip string) {
	ipVerifier := regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$`)
	if !ipVerifier.MatchString(ip) {
		log.Fatalf("Failed to validate ip address: %s", ip)
	}

}

func validatePortNumber(port string) {
	val, err := strconv.ParseInt(port, 10, 64)
	if err != nil || val < 0 || val > 65535 {
		log.Fatalf("Failed parsing port number: %s [valid values are 0-65535]", port)
	}
}

func validateEmptyValue(field, value string) {
	if value != "" {
		log.Fatalf("Field %s does not take a value, value passed was: %s", field, value)
	}
}

func validateDSCPValue(value string) {
	val, err := strconv.ParseInt(value, 10, 64)
	if err != nil || val < 0 || val > 63 {
		log.Fatalf("Failed parsing dscp number: %s [valid values are 0-63]", value)
	}
}
