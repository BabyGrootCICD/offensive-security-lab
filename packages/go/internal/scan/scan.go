// Package scan 只讀 Go 原始碼，標出可能讓不可信輸入決定 HTTP client 目的地的寫法。
// 它不會建立網路連線，也不會產生可送出的請求。
package scan

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"offensive-security-lab/packages/go/internal/report"
	"offensive-security-lab/packages/go/internal/rules"
)

var privilegedName = regexp.MustCompile(`(?i)admin|delete|manage`)

var skipDirs = map[string]struct{}{
	"vendor":       {},
	"node_modules": {},
	"dist":         {},
	"target":       {},
	".git":         {},
}

// Scan 掃描檔案或目錄，回傳相對路徑的發現。
func Scan(path string, ruleSet *rules.Set) ([]report.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat scan path: %w", err)
	}
	if !info.IsDir() {
		findings, err := scanFile(path, filepath.Dir(path), ruleSet)
		if err != nil {
			return nil, err
		}
		return findings, nil
	}
	var findings []report.Finding
	err = filepath.WalkDir(path, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, skip := skipDirs[entry.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		fileFindings, err := scanFile(name, path, ruleSet)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if findings == nil {
		findings = []report.Finding{}
	}
	return findings, nil
}

func scanFile(filename, root string, ruleSet *rules.Set) ([]report.Finding, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Uses:  make(map[*ast.Ident]types.Object),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default(), Error: func(error) {}}
	_, _ = conf.Check(file.Name.Name, fset, []*ast.File{file}, info)

	rel := filename
	if relPath, err := filepath.Rel(root, filename); err == nil {
		rel = relPath
	}
	ctx := &fileContext{fset: fset, src: src, info: info, file: rel, rules: ruleSet}
	var decls []*ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok {
			decls = append(decls, fn)
		}
	}
	var findings []report.Finding
	for _, fn := range decls {
		findings = append(findings, scanBody(fn.Name.Name, fn.Body, ctx)...)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok || lit.Body == nil || coveredByFunc(lit.Pos(), decls) {
			return true
		}
		findings = append(findings, scanBody("anonymous", lit.Body, ctx)...)
		return true
	})
	return findings, nil
}

func coveredByFunc(pos token.Pos, decls []*ast.FuncDecl) bool {
	for _, decl := range decls {
		if decl.Body != nil && decl.Pos() <= pos && pos <= decl.End() {
			return true
		}
	}
	return false
}

type fileContext struct {
	fset  *token.FileSet
	src   []byte
	info  *types.Info
	file  string
	rules *rules.Set
}

type sinkUse struct {
	name     string
	call     *ast.CallExpr
	url      ast.Expr
	constant bool
}

func scanBody(name string, body *ast.BlockStmt, ctx *fileContext) []report.Finding {
	if body == nil {
		return nil
	}
	sinks := collectSinks(body, ctx.info)
	var findings []report.Finding
	if !hasExactAllowlist(body, ctx.info) {
		for _, sink := range sinks {
			if sink.constant {
				continue
			}
			findings = append(findings, ctx.finding("SSRF-001", sink.call.Pos(), describeSource(body, sink.url, sink.call.Pos()), sink.name))
		}
	}
	if len(sinks) > 0 {
		if node := denylistNode(body, ctx.info); node != nil {
			findings = append(findings, ctx.finding("SSRF-002", node.Pos(), exprString(node), firstSinkName(sinks)))
		}
		if node := substringNode(body, ctx.info); node != nil {
			findings = append(findings, ctx.finding("SSRF-003", node.Pos(), exprString(node), firstSinkName(sinks)))
		}
		if node := openRedirectNode(body); node != nil {
			findings = append(findings, ctx.finding("SSRF-004", node.Pos(), "CheckRedirect returns nil", firstSinkName(sinks)))
		}
	}
	if privilegedName.MatchString(name) && hasLoopbackTrust(body) {
		findings = append(findings, ctx.finding("SSRF-005", body.Pos(), "loopback source", name))
	}
	return findings
}

func (ctx *fileContext) finding(id string, pos token.Pos, source, sink string) report.Finding {
	rule, err := ctx.rules.Get(id)
	if err != nil {
		rule = rules.Rule{ID: id, Severity: "medium", Title: id}
	}
	position := ctx.fset.Position(pos)
	line := position.Line
	if line < 1 {
		line = 1
	}
	return report.Finding{
		RuleID:      rule.ID,
		Severity:    rule.Severity,
		Title:       rule.Title,
		File:        ctx.file,
		Line:        line,
		Source:      truncate(source),
		Sink:        sink,
		Impact:      rule.Impact,
		Remediation: rule.Remediation,
		Snippet:     lineSnippet(ctx.src, line),
	}
}

func collectSinks(body *ast.BlockStmt, info *types.Info) []sinkUse {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			calls = append(calls, call)
		}
		return true
	})
	var sinks []sinkUse
	for _, call := range calls {
		full, urlArg, ok := classifySink(call.Fun, info)
		if !ok {
			continue
		}
		if urlArg < 0 {
			if linkedNewRequest(call, calls, info) {
				continue
			}
			urlArg = 0
		}
		if urlArg >= len(call.Args) {
			continue
		}
		urlExpr := call.Args[urlArg]
		sinks = append(sinks, sinkUse{
			name:     full,
			call:     call,
			url:      urlExpr,
			constant: isConstantString(urlExpr, info),
		})
	}
	return sinks
}

func linkedNewRequest(doCall *ast.CallExpr, _ []*ast.CallExpr, info *types.Info) bool {
	if len(doCall.Args) == 0 {
		return false
	}
	nested, ok := doCall.Args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	_, urlArg, isSink := classifySink(nested.Fun, info)
	return isSink && urlArg >= 0
}

func classifySink(fun ast.Expr, info *types.Info) (string, int, bool) {
	if info != nil {
		if obj := usedObject(fun, info); obj != nil {
			fn, ok := obj.(*types.Func)
			if !ok {
				return "", 0, false
			}
			return sinkFromFullName(fn.FullName())
		}
	}
	return syntacticHTTPSink(fun)
}

func usedObject(fun ast.Expr, info *types.Info) types.Object {
	switch f := fun.(type) {
	case *ast.Ident:
		return info.Uses[f]
	case *ast.SelectorExpr:
		return info.Uses[f.Sel]
	default:
		return nil
	}
}

func sinkFromFullName(full string) (string, int, bool) {
	switch full {
	case "net/http.Get", "net/http.Head",
		"(*net/http.Client).Get", "(net/http.Client).Get",
		"(*net/http.Client).Head", "(net/http.Client).Head":
		return full, 0, true
	case "net/http.Post", "(*net/http.Client).Post", "(net/http.Client).Post":
		return full, 0, true
	case "net/http.NewRequest":
		return full, 1, true
	case "net/http.NewRequestWithContext":
		return full, 2, true
	case "(*net/http.Client).Do", "(net/http.Client).Do":
		return full, -1, true
	default:
		return "", 0, false
	}
}

func syntacticHTTPSink(fun ast.Expr) (string, int, bool) {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || !isHTTPSelector(sel) {
		return "", 0, false
	}
	switch sel.Sel.Name {
	case "Get", "Head", "Post":
		return "net/http." + sel.Sel.Name, 0, true
	case "NewRequest":
		return "net/http.NewRequest", 1, true
	case "NewRequestWithContext":
		return "net/http.NewRequestWithContext", 2, true
	case "Do":
		return "(*net/http.Client).Do", -1, true
	default:
		return "", 0, false
	}
}

func isHTTPSelector(sel *ast.SelectorExpr) bool {
	switch x := sel.X.(type) {
	case *ast.Ident:
		return x.Name == "http" || x.Name == "client"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Client" || x.Sel.Name == "DefaultClient"
	default:
		return false
	}
}

func isConstantString(expr ast.Expr, info *types.Info) bool {
	if expr == nil {
		return false
	}
	if info != nil {
		if tv, ok := info.Types[expr]; ok && tv.Value != nil {
			return true
		}
	}
	_, ok := expr.(*ast.BasicLit)
	return ok
}

func hasExactAllowlist(body *ast.BlockStmt, info *types.Info) bool {
	hasParse := false
	hasHost := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isURLParse(call, info) {
			hasParse = true
		}
		if ok && isExactHostEqualFold(call) {
			hasHost = true
		}
		bin, ok := n.(*ast.BinaryExpr)
		if ok && (bin.Op == token.EQL || bin.Op == token.NEQ) && exactHostCompare(bin) {
			hasHost = true
		}
		return true
	})
	return hasParse && hasHost
}

func isURLParse(call *ast.CallExpr, info *types.Info) bool {
	if info != nil {
		if obj := usedObject(call.Fun, info); obj != nil {
			if fn, ok := obj.(*types.Func); ok {
				switch fn.FullName() {
				case "net/url.Parse", "net/url.ParseRequestURI":
					return true
				}
			}
		}
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "url" && (sel.Sel.Name == "Parse" || sel.Sel.Name == "ParseRequestURI")
}

func exactHostCompare(bin *ast.BinaryExpr) bool {
	lit, expr, ok := literalAndOther(bin.X, bin.Y)
	if !ok || isDenylistLiteral(lit) || !isHostExpr(expr) {
		return false
	}
	return true
}

func isExactHostEqualFold(call *ast.CallExpr) bool {
	if !isStringsFunc(call.Fun, "EqualFold") || len(call.Args) != 2 {
		return false
	}
	lit, expr, ok := literalAndOther(call.Args[0], call.Args[1])
	return ok && !isDenylistLiteral(lit) && isHostExpr(expr)
}

func literalAndOther(left, right ast.Expr) (string, ast.Expr, bool) {
	if lit, ok := stringLiteral(left); ok {
		return lit, right, true
	}
	if lit, ok := stringLiteral(right); ok {
		return lit, left, true
	}
	return "", nil, false
}

func isHostExpr(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name == "Host" || x.Sel.Name == "Hostname"
	case *ast.Ident:
		return strings.EqualFold(x.Name, "host") || strings.EqualFold(x.Name, "hostname")
	case *ast.CallExpr:
		switch fun := x.Fun.(type) {
		case *ast.SelectorExpr:
			return fun.Sel.Name == "Hostname" || fun.Sel.Name == "Host"
		case *ast.Ident:
			return fun.Name == "Hostname"
		}
	}
	return false
}

func denylistNode(body *ast.BlockStmt, info *types.Info) ast.Expr {
	var found ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isDenylistCall(call, info) {
			return true
		}
		found = call
		return true
	})
	return found
}

func substringNode(body *ast.BlockStmt, info *types.Info) ast.Expr {
	var found ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSubstringAllowlist(call, info) {
			return true
		}
		found = call
		return true
	})
	return found
}

func isDenylistCall(call *ast.CallExpr, info *types.Info) bool {
	if !isHostStringMatch(call, info) {
		return false
	}
	for _, arg := range call.Args {
		lit, ok := stringLiteral(arg)
		if ok && isDenylistLiteral(lit) {
			return true
		}
	}
	return false
}

func isSubstringAllowlist(call *ast.CallExpr, info *types.Info) bool {
	name := stringsFuncName(call.Fun, info)
	switch name {
	case "Contains", "HasPrefix", "HasSuffix":
	default:
		return false
	}
	if len(call.Args) != 2 {
		return false
	}
	lit, other, ok := literalAndOther(call.Args[0], call.Args[1])
	if !ok || isDenylistLiteral(lit) || !isHostLike(other) {
		return false
	}
	return true
}

func isHostStringMatch(call *ast.CallExpr, info *types.Info) bool {
	switch stringsFuncName(call.Fun, info) {
	case "Contains", "HasPrefix", "HasSuffix", "EqualFold":
		return true
	default:
		return false
	}
}

func stringsFuncName(fun ast.Expr, info *types.Info) string {
	if info != nil {
		if obj := usedObject(fun, info); obj != nil {
			fn, ok := obj.(*types.Func)
			if !ok {
				return ""
			}
			full := fn.FullName()
			if !strings.HasPrefix(full, "strings.") {
				return ""
			}
			return strings.TrimPrefix(full, "strings.")
		}
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "strings" {
		return ""
	}
	return sel.Sel.Name
}

func isStringsFunc(fun ast.Expr, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "strings"
}

func isHostLike(expr ast.Expr) bool {
	if isHostExpr(expr) {
		return true
	}
	switch x := expr.(type) {
	case *ast.Ident:
		switch strings.ToLower(x.Name) {
		case "raw", "url", "uri", "dest", "target", "endpoint", "addr", "address", "stockapi":
			return true
		}
	case *ast.SelectorExpr:
		return isHostLike(x.X) || isHostLike(x.Sel)
	case *ast.CallExpr:
		return isHostLike(x.Fun)
	}
	return false
}

func isDenylistLiteral(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "localhost", "127.0.0.1":
		return true
	default:
		return false
	}
}

func openRedirectNode(body *ast.BlockStmt) ast.Node {
	var found ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isHTTPClientType(lit.Type) {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "CheckRedirect" {
				continue
			}
			if checkRedirectFollowsAll(kv.Value) {
				found = kv.Value
			}
		}
		return true
	})
	return found
}

func isHTTPClientType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Client" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "http"
}

func checkRedirectFollowsAll(expr ast.Expr) bool {
	if id, ok := expr.(*ast.Ident); ok && id.Name == "nil" {
		return true
	}
	fn, ok := expr.(*ast.FuncLit)
	if !ok || fn.Body == nil {
		return false
	}
	sawNil := false
	bad := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) == 1 {
			if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
				sawNil = true
				return true
			}
		}
		if len(ret.Results) > 0 {
			bad = true
		}
		return true
	})
	return sawNil && !bad
}

func hasLoopbackTrust(body *ast.BlockStmt) bool {
	remote := false
	loopCall := false
	literal := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && (sel.Sel.Name == "RemoteAddr" || sel.Sel.Name == "IsLoopback") {
			if sel.Sel.Name == "RemoteAddr" {
				remote = true
			}
			if sel.Sel.Name == "IsLoopback" {
				loopCall = true
			}
		}
		if expr, ok := n.(ast.Expr); ok {
			if lit, ok := stringLiteral(expr); ok && isDenylistLiteral(lit) {
				literal = true
			}
		}
		return true
	})
	return loopCall || (remote && literal)
}

func describeSource(body *ast.BlockStmt, expr ast.Expr, before token.Pos) string {
	if expr == nil {
		return ""
	}
	if id, ok := expr.(*ast.Ident); ok {
		if rhs := findAssign(body, id.Name, before); rhs != nil {
			return exprString(rhs)
		}
	}
	return exprString(expr)
}

func findAssign(body *ast.BlockStmt, name string, before token.Pos) ast.Expr {
	var found ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() >= before {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if ok && id.Name == name && i < len(assign.Rhs) {
				found = assign.Rhs[i]
			}
		}
		return true
	})
	return found
}

func firstSinkName(sinks []sinkUse) string {
	if len(sinks) == 0 {
		return ""
	}
	return sinks[0].name
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func exprString(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var buf strings.Builder
	if err := printer.Fprint(&buf, token.NewFileSet(), expr); err != nil {
		return ""
	}
	return truncate(buf.String())
}

func lineSnippet(src []byte, line int) string {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return truncate(strings.TrimSpace(lines[line-1]))
}

func truncate(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 200 {
		return value[:200]
	}
	return value
}
