
```
Fields:
	- srv.ip <value>
	- cli.ip <value>
	- srv.tcp.port <value>
	- srv.udp.port <value>
	- cli.tcp.port <value>
	- cli.udp.port <value>
    - srv.icmp.port <value>
    - cli.icmp.port <value>
	- proto.icmp
	- proto.tcp
	- proto.udp
	- ip.dscp <value>

Operators:
	- AND
	- OR
	- NOT
	- ==

* Intentionally not supporting grouping right now
```

```
Order of operations
    1. OR - this operation should be done first, it essentially means create two rules in this context.
            remember that any AND's will distribute to both OR expressions
    2. AND - this operation just combines the things from the left and right into one rule
```

```
	topNode := parser.AND{
		Left:  parser.OR{
			parser.EQ{"srv.ip", "1.2.3.4"},
			parser.EQ{"srv.ip", "5.6.7.8"},
		},
		Right: parser.AND{
			parser.EQ{"proto.tcp", ""},
			parser.NOT{parser.OR{
				parser.EQ{"srv.tcp.port", "443"},
				parser.EQ{"srv.tcp.port", "80"},
			}},
		},
	}

	filters := topNode.Eval()
	fmt.Println("Uplink Filters")
	for idx, ulFilter := range(filters.ULFilters) {
		fmt.Printf("%d: %s\n", idx, ulFilter)
	}
	fmt.Println("Downlink Filters")
	for idx, dlFilter := range(filters.DLFilters) {
		fmt.Printf("%d: %s\n", idx, dlFilter)
	}
```