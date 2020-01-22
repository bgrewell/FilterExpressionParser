package parser

import (
	"reflect"
	"testing"
)

func TestFilterParser_Parse(t *testing.T) {
	type fields struct {
		InputExpression string
	}
	type args struct {
		expression string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantFilterTree IPTablesFilters
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &FilterParser{
				InputExpression: tt.fields.InputExpression,
			}
			if gotFilterTree := fp.Parse(tt.args.expression); !reflect.DeepEqual(gotFilterTree, tt.wantFilterTree) {
				t.Errorf("Parse() = %v, want %v", gotFilterTree, tt.wantFilterTree)
			}
		})
	}
}