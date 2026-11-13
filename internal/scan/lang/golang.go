package lang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"strings"
)

var strongSinkPackages = map[string]bool{"log": true, "slog": true, "fmt": true, "errors": true, "http": true}

var loggerMethods = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Error": true, "Errorf": true, "Info": true, "Infof": true,
	"Warn": true, "Warnf": true, "Debug": true, "Debugf": true,
	"Fatal": true, "Fatalf": true, "Panic": true, "Panicf": true,
	"Msg": true, "Msgf": true, "Write": true, "WriteString": true,
}

type goState struct {
	fset         *token.FileSet
	extractor    *Extractor
	imports      map[string]string
	tainted      map[string]string
	taintedField map[string]string
	facts        Facts
}

func (e *Extractor) extractGo(data []byte) (Facts, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", data, parser.SkipObjectResolution)
	if err != nil {
		return Facts{}, fmt.Errorf("parse go source: %w", err)
	}
	state := &goState{
		fset:         fset,
		extractor:    e,
		imports:      e.goImports(file),
		tainted:      make(map[string]string),
		taintedField: make(map[string]string),
	}
	ast.Inspect(file, state.visit)
	return state.facts, nil
}

func (e *Extractor) goImports(file *ast.File) map[string]string {
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		for _, rule := range e.clients[Go] {
			if rule.Import != importPath {
				continue
			}
			local := rule.Package
			if spec.Name != nil {
				local = spec.Name.Name
			}
			imports[local] = rule.Provider
		}
	}
	return imports
}

func (s *goState) visit(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.AssignStmt:
		s.recordAssignment(n.Lhs, n.Rhs)
	case *ast.ValueSpec:
		names := make([]ast.Expr, len(n.Names))
		for i, name := range n.Names {
			names[i] = name
		}
		s.recordAssignment(names, n.Values)
	case *ast.KeyValueExpr:
		if name, ok := s.envReadName(n.Value); ok {
			if key, isIdent := n.Key.(*ast.Ident); isIdent {
				s.taintedField[key.Name] = name
			}
		}
	case *ast.CallExpr:
		s.recordClient(n)
		s.recordEnvRead(n)
		s.recordLeak(n)
	}
	return true
}

func (s *goState) recordAssignment(lhs, rhs []ast.Expr) {
	if len(rhs) == 1 && len(lhs) >= 1 {
		if name, ok := s.envReadName(rhs[0]); ok {
			s.tainted[types.ExprString(lhs[0])] = name
		}
		return
	}
	for i := range min(len(lhs), len(rhs)) {
		if name, ok := s.envReadName(rhs[i]); ok {
			s.tainted[types.ExprString(lhs[i])] = name
		}
	}
}

func (s *goState) envReadName(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "os" || (selector.Sel.Name != "Getenv" && selector.Sel.Name != "LookupEnv") {
		return "", false
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	name, err := strconv.Unquote(literal.Value)
	if err != nil || !s.extractor.isCredentialEnv(name) {
		return "", false
	}
	return name, true
}

func (s *goState) recordEnvRead(call *ast.CallExpr) {
	if name, ok := s.envReadName(call); ok {
		s.facts.EnvReads = append(s.facts.EnvReads, EnvRead{Name: name, Line: s.line(call)})
	}
}

func (s *goState) recordClient(call *ast.CallExpr) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "New") {
		return
	}
	if provider, known := s.imports[pkg.Name]; known {
		s.facts.Clients = append(s.facts.Clients, Client{
			Provider:    provider,
			Constructor: pkg.Name + "." + selector.Sel.Name,
			Line:        s.line(call),
		})
	}
}

func (s *goState) recordLeak(call *ast.CallExpr) {
	sink, strong, ok := sinkName(call)
	if !ok {
		return
	}
	for _, arg := range call.Args {
		if env, variable, found := s.taintOf(arg); found {
			s.facts.Leaks = append(s.facts.Leaks, Leak{
				Env:      env,
				Variable: variable,
				Sink:     sink,
				Line:     s.line(call),
				Strong:   strong,
			})
			return
		}
	}
}

func sinkName(call *ast.CallExpr) (string, bool, bool) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if fun.Name == "panic" {
			return "panic", true, true
		}
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok && strongSinkPackages[pkg.Name] {
			if pkg.Name == "fmt" && !strings.HasPrefix(fun.Sel.Name, "Print") && !strings.HasPrefix(fun.Sel.Name, "Fprint") && fun.Sel.Name != "Errorf" {
				return "", false, false
			}
			if pkg.Name == "errors" && fun.Sel.Name != "New" {
				return "", false, false
			}
			if pkg.Name == "http" && fun.Sel.Name != "Error" {
				return "", false, false
			}
			return pkg.Name + "." + fun.Sel.Name, true, true
		}
		if loggerMethods[fun.Sel.Name] {
			return types.ExprString(fun), false, true
		}
	}
	return "", false, false
}

func (s *goState) taintOf(expr ast.Expr) (env, variable string, found bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		if name, ok := s.tainted[e.Name]; ok {
			return name, e.Name, true
		}
	case *ast.SelectorExpr:
		if name, ok := s.tainted[types.ExprString(e)]; ok {
			return name, types.ExprString(e), true
		}
		if name, ok := s.taintedField[e.Sel.Name]; ok {
			return name, types.ExprString(e), true
		}
	case *ast.BinaryExpr:
		if env, variable, found = s.taintOf(e.X); found {
			return env, variable, true
		}
		return s.taintOf(e.Y)
	case *ast.ParenExpr:
		return s.taintOf(e.X)
	case *ast.CallExpr:
		if name, ok := s.envReadName(e); ok {
			return name, "", true
		}
		if isFormatCall(e) {
			for _, arg := range e.Args {
				if env, variable, found = s.taintOf(arg); found {
					return env, variable, true
				}
			}
		}
	}
	return "", "", false
}

func isFormatCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "fmt" && strings.HasPrefix(selector.Sel.Name, "Sprint")
}

func (s *goState) line(node ast.Node) int {
	return s.fset.Position(node.Pos()).Line
}
