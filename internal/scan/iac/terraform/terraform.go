package terraform

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type Attribute struct {
	Name string
	Line int
	expr hclsyntax.Expression
}

type Block struct {
	Type   string
	Labels []string
	Path   string
	Line   int
	Attrs  map[string]*Attribute
	Blocks []*Block
}

func (b *Block) Address() string {
	switch b.Type {
	case "resource":
		return strings.Join(b.Labels, ".")
	case "data":
		return "data." + strings.Join(b.Labels, ".")
	}
	return b.Type + "." + strings.Join(b.Labels, ".")
}

func (b *Block) Attr(name string) (*Attribute, bool) {
	attribute, ok := b.Attrs[name]
	return attribute, ok
}

func (b *Block) Children(blockType string) []*Block {
	var out []*Block
	for _, child := range b.Blocks {
		if child.Type == blockType {
			out = append(out, child)
		}
	}
	return out
}

type Module struct {
	Directory string
	blocks    []*Block
	files     map[string][]byte
	variables map[string]*Attribute
	tfvars    map[string]*Attribute
	locals    map[string]*Attribute
}

func NewModule(directory string) *Module {
	return &Module{
		Directory: directory,
		files:     make(map[string][]byte),
		variables: make(map[string]*Attribute),
		tfvars:    make(map[string]*Attribute),
		locals:    make(map[string]*Attribute),
	}
}

func (m *Module) AddFile(filePath string, data []byte) error {
	m.files[path.Base(filePath)] = data
	if strings.HasSuffix(filePath, ".tfvars") {
		return m.addTfvars(filePath, data)
	}
	file, diagnostics := hclsyntax.ParseConfig(data, filePath, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return fmt.Errorf("parse %s: %s", filePath, diagnostics.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("parse %s: unexpected body type", filePath)
	}
	for _, block := range body.Blocks {
		converted := convertBlock(filePath, block)
		m.blocks = append(m.blocks, converted)
		switch converted.Type {
		case "variable":
			if len(converted.Labels) == 1 {
				if attribute, found := converted.Attr("default"); found {
					m.variables[converted.Labels[0]] = attribute
				}
			}
		case "locals":
			for name, attribute := range converted.Attrs {
				m.locals[name] = attribute
			}
		}
	}
	return nil
}

func (m *Module) addTfvars(filePath string, data []byte) error {
	file, diagnostics := hclsyntax.ParseConfig(data, filePath, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return fmt.Errorf("parse %s: %s", filePath, diagnostics.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("parse %s: unexpected body type", filePath)
	}
	for name, attribute := range body.Attributes {
		m.tfvars[name] = &Attribute{Name: name, Line: attribute.SrcRange.Start.Line, expr: attribute.Expr}
	}
	return nil
}

func convertBlock(filePath string, block *hclsyntax.Block) *Block {
	converted := &Block{
		Type:   block.Type,
		Labels: append([]string(nil), block.Labels...),
		Path:   filePath,
		Line:   block.TypeRange.Start.Line,
		Attrs:  make(map[string]*Attribute, len(block.Body.Attributes)),
	}
	for name, attribute := range block.Body.Attributes {
		converted.Attrs[name] = &Attribute{Name: name, Line: attribute.SrcRange.Start.Line, expr: attribute.Expr}
	}
	for _, child := range block.Body.Blocks {
		converted.Blocks = append(converted.Blocks, convertBlock(filePath, child))
	}
	return converted
}

func (m *Module) Blocks() []*Block {
	return append([]*Block(nil), m.blocks...)
}

func (m *Module) Resources(resourceType string) []*Block {
	var out []*Block
	for _, block := range m.blocks {
		if block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == resourceType {
			out = append(out, block)
		}
	}
	return out
}

func (m *Module) DataSources(dataType string) []*Block {
	var out []*Block
	for _, block := range m.blocks {
		if block.Type == "data" && len(block.Labels) == 2 && block.Labels[0] == dataType {
			out = append(out, block)
		}
	}
	return out
}

func (m *Module) Find(address string) (*Block, bool) {
	for _, block := range m.blocks {
		if (block.Type == "resource" || block.Type == "data") && block.Address() == address {
			return block, true
		}
	}
	return nil, false
}

func (m *Module) ResourceTypes() []string {
	seen := make(map[string]bool)
	for _, block := range m.blocks {
		if block.Type == "resource" && len(block.Labels) == 2 {
			seen[block.Labels[0]] = true
		}
	}
	types := make([]string, 0, len(seen))
	for resourceType := range seen {
		types = append(types, resourceType)
	}
	sort.Strings(types)
	return types
}

func (attribute *Attribute) Reference() (string, bool) {
	traversal, diagnostics := hcl.AbsTraversalForExpr(attribute.expr)
	if diagnostics.HasErrors() || len(traversal) < 3 {
		return "", false
	}
	root := traversal.RootName()
	first, ok := traversal[1].(hcl.TraverseAttr)
	if !ok {
		return "", false
	}
	if root == "data" {
		second, isAttr := traversal[2].(hcl.TraverseAttr)
		if !isAttr {
			return "", false
		}
		return fmt.Sprintf("data.%s.%s", first.Name, second.Name), true
	}
	return fmt.Sprintf("%s.%s", root, first.Name), true
}

func (attribute *Attribute) References() []string {
	tuple, ok := attribute.expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		if reference, found := attribute.Reference(); found {
			return []string{reference}
		}
		return nil
	}
	var out []string
	for _, element := range tuple.Exprs {
		elementAttribute := &Attribute{Name: attribute.Name, Line: attribute.Line, expr: element}
		if reference, found := elementAttribute.Reference(); found {
			out = append(out, reference)
		}
	}
	return out
}
