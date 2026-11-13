package terraform

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

const (
	maxEvalDepth      = 8
	unresolvedPattern = "<unresolved:%s>"
)

func (m *Module) functions() map[string]function.Function {
	return map[string]function.Function{
		"jsonencode": stdlib.JSONEncodeFunc,
		"format":     stdlib.FormatFunc,
		"join":       stdlib.JoinFunc,
		"concat":     stdlib.ConcatFunc,
		"lower":      stdlib.LowerFunc,
		"upper":      stdlib.UpperFunc,
		"merge":      stdlib.MergeFunc,
		"flatten":    stdlib.FlattenFunc,
		"keys":       stdlib.KeysFunc,
		"values":     stdlib.ValuesFunc,
		"compact":    stdlib.CompactFunc,
		"distinct":   stdlib.DistinctFunc,
		"coalesce":   stdlib.CoalesceFunc,
		"length":     stdlib.LengthFunc,
		"tolist":     stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
		"toset":      stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
		"file":       m.fileFunction(),
	}
}

func (m *Module) fileFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			name := args[0].AsString()
			data, ok := m.files[baseName(name)]
			if !ok {
				return cty.UnknownVal(cty.String), fmt.Errorf("file %q is not part of the scanned module", name)
			}
			return cty.StringVal(string(data)), nil
		},
	})
}

func baseName(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' || name[i] == '\\' {
			return name[i+1:]
		}
	}
	return name
}

type placeholderTree map[string]any

func (t placeholderTree) insert(steps []string, leaf string) {
	node := t
	for i, step := range steps {
		if i == len(steps)-1 {
			node[step] = leaf
			return
		}
		child, ok := node[step].(placeholderTree)
		if !ok {
			child = placeholderTree{}
			node[step] = child
		}
		node = child
	}
}

func (t placeholderTree) value() map[string]cty.Value {
	out := make(map[string]cty.Value, len(t))
	for name, node := range t {
		switch typed := node.(type) {
		case string:
			out[name] = cty.StringVal(typed)
		case placeholderTree:
			out[name] = cty.ObjectVal(typed.value())
		}
	}
	return out
}

func (m *Module) context(attribute *Attribute, depth int) *hcl.EvalContext {
	variables := make(map[string]cty.Value)
	tree := placeholderTree{}
	vars := make(map[string]cty.Value)
	locals := make(map[string]cty.Value)

	for _, traversal := range attribute.expr.Variables() {
		root := traversal.RootName()
		steps := traversalSteps(traversal)
		switch root {
		case "var":
			if len(steps) > 0 {
				vars[steps[0]] = m.variableValue(steps[0], depth)
			}
		case "local":
			if len(steps) > 0 {
				locals[steps[0]] = m.localValue(steps[0], depth)
			}
		case "path", "terraform", "count", "each", "self":
			tree.insert(append([]string{root}, steps...), fmt.Sprintf(unresolvedPattern, root))
		default:
			tree.insert(append([]string{root}, steps...), fmt.Sprintf(unresolvedPattern, joinSteps(root, steps)))
		}
	}
	for name, value := range tree.value() {
		variables[name] = value
	}
	variables["var"] = cty.ObjectVal(nonEmpty(vars))
	variables["local"] = cty.ObjectVal(nonEmpty(locals))
	return &hcl.EvalContext{Variables: variables, Functions: m.functions()}
}

func nonEmpty(values map[string]cty.Value) map[string]cty.Value {
	if values == nil {
		return map[string]cty.Value{}
	}
	return values
}

func traversalSteps(traversal hcl.Traversal) []string {
	var steps []string
	for _, step := range traversal[1:] {
		attr, ok := step.(hcl.TraverseAttr)
		if !ok {
			break
		}
		steps = append(steps, attr.Name)
	}
	return steps
}

func joinSteps(root string, steps []string) string {
	joined := root
	for _, step := range steps {
		joined += "." + step
	}
	return joined
}

func (m *Module) variableValue(name string, depth int) cty.Value {
	source, ok := m.tfvars[name]
	if !ok {
		source, ok = m.variables[name]
	}
	if !ok || depth >= maxEvalDepth {
		return cty.StringVal(fmt.Sprintf(unresolvedPattern, "var."+name))
	}
	value, known := m.eval(source, depth+1)
	if !known {
		return cty.StringVal(fmt.Sprintf(unresolvedPattern, "var."+name))
	}
	return value
}

func (m *Module) localValue(name string, depth int) cty.Value {
	source, ok := m.locals[name]
	if !ok || depth >= maxEvalDepth {
		return cty.StringVal(fmt.Sprintf(unresolvedPattern, "local."+name))
	}
	value, known := m.eval(source, depth+1)
	if !known {
		return cty.StringVal(fmt.Sprintf(unresolvedPattern, "local."+name))
	}
	return value
}

func (m *Module) eval(attribute *Attribute, depth int) (cty.Value, bool) {
	value, diagnostics := attribute.expr.Value(m.context(attribute, depth))
	if diagnostics.HasErrors() || !value.IsWhollyKnown() {
		return cty.NilVal, false
	}
	return value, true
}

func (m *Module) Eval(attribute *Attribute) (cty.Value, bool) {
	return m.eval(attribute, 0)
}

func (m *Module) Text(attribute *Attribute) (string, bool) {
	value, known := m.Eval(attribute)
	if !known || value.IsNull() || value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

func (m *Module) Bool(attribute *Attribute) (bool, bool) {
	value, known := m.Eval(attribute)
	if !known || value.IsNull() || value.Type() != cty.Bool {
		return false, false
	}
	return value.True(), true
}

func (m *Module) Strings(attribute *Attribute) []string {
	value, known := m.Eval(attribute)
	if !known || value.IsNull() {
		return nil
	}
	return stringsOf(value)
}

func (m *Module) Number(attribute *Attribute) (float64, bool) {
	value, known := m.Eval(attribute)
	if !known || value.IsNull() || value.Type() != cty.Number {
		return 0, false
	}
	number, _ := value.AsBigFloat().Float64()
	return number, true
}

func stringsOf(value cty.Value) []string {
	switch {
	case value.Type() == cty.String:
		return []string{value.AsString()}
	case value.Type().IsListType() || value.Type().IsSetType() || value.Type().IsTupleType():
		var out []string
		for iterator := value.ElementIterator(); iterator.Next(); {
			_, element := iterator.Element()
			if element.Type() == cty.String && !element.IsNull() {
				out = append(out, element.AsString())
			}
		}
		return out
	}
	return nil
}

func (m *Module) StringMap(attribute *Attribute) map[string]string {
	value, known := m.Eval(attribute)
	if !known || value.IsNull() || !value.Type().IsObjectType() && !value.Type().IsMapType() {
		return nil
	}
	out := make(map[string]string)
	for iterator := value.ElementIterator(); iterator.Next(); {
		key, element := iterator.Element()
		if element.Type() == cty.String && !element.IsNull() {
			out[key.AsString()] = element.AsString()
		}
	}
	return out
}

func SortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
