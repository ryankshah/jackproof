package terraform

import (
	"reflect"
	"strings"
	"testing"
)

const sample = `
variable "region" {
  default = "us-east-1"
}

variable "budget" {}

variable "actions" {
  default = ["bedrock:InvokeModel", "bedrock:Converse"]
}

locals {
  prefix = "llm-${var.region}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = var.actions
      Resource = aws_s3_bucket.logs.arn
    }]
  })
}

resource "aws_iam_role" "app" {
  name = "${local.prefix}-app"
  inline_policy {
    name   = "invoke"
    policy = local.policy
  }
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.invoke.arn
}

data "aws_iam_policy_document" "doc" {
  statement {
    actions   = ["bedrock:*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "raw" {
  policy = <<-EOT
    {"Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "${aws_s3_bucket.logs.arn}"}]}
  EOT
}
`

func loadSample(t *testing.T) *Module {
	t.Helper()
	module := NewModule("infra")
	if err := module.AddFile("infra/main.tf", []byte(sample)); err != nil {
		t.Fatal(err)
	}
	return module
}

func TestBlocksAndAddresses(t *testing.T) {
	module := loadSample(t)
	if got := len(module.Resources("aws_iam_role")); got != 1 {
		t.Fatalf("roles = %d", got)
	}
	role := module.Resources("aws_iam_role")[0]
	if role.Address() != "aws_iam_role.app" || role.Path != "infra/main.tf" || role.Line != 24 {
		t.Errorf("role = %+v", role)
	}
	if len(role.Children("inline_policy")) != 1 {
		t.Errorf("children = %+v", role.Blocks)
	}
	doc, ok := module.Find("data.aws_iam_policy_document.doc")
	if !ok || len(doc.Children("statement")) != 1 {
		t.Errorf("document = %+v, %v", doc, ok)
	}
	if got := len(module.DataSources("aws_iam_policy_document")); got != 1 {
		t.Errorf("data sources = %d", got)
	}
	if !reflect.DeepEqual(module.ResourceTypes(), []string{"aws_iam_policy", "aws_iam_role", "aws_iam_role_policy_attachment"}) {
		t.Errorf("types = %v", module.ResourceTypes())
	}
	if _, ok := module.Find("aws_iam_role.missing"); ok {
		t.Error("found a resource that does not exist")
	}
	if len(module.Blocks()) == 0 {
		t.Error("no blocks")
	}
}

func TestEvaluation(t *testing.T) {
	module := loadSample(t)
	role := module.Resources("aws_iam_role")[0]
	name, _ := role.Attr("name")
	if text, ok := module.Text(name); !ok || text != "llm-us-east-1-app" {
		t.Errorf("name = %q, %v", text, ok)
	}

	inline := role.Children("inline_policy")[0]
	policy, _ := inline.Attr("policy")
	text, ok := module.Text(policy)
	if !ok {
		t.Fatal("policy did not evaluate")
	}
	for _, want := range []string{`"bedrock:InvokeModel"`, `"bedrock:Converse"`, "unresolved:aws_s3_bucket.logs.arn", `"2012-10-17"`} {
		if !strings.Contains(text, want) {
			t.Errorf("policy lacks %s: %s", want, text)
		}
	}

	raw := module.Resources("aws_iam_policy")[0]
	rawPolicy, _ := raw.Attr("policy")
	rawText, ok := module.Text(rawPolicy)
	if !ok || !strings.Contains(rawText, "<unresolved:aws_s3_bucket.logs.arn>") || !strings.Contains(rawText, `"bedrock:*"`) {
		t.Errorf("heredoc = %q, %v", rawText, ok)
	}
}

func TestTypedEvaluators(t *testing.T) {
	module := NewModule("x")
	source := `
resource "r" "t" {
  on       = true
  count_n  = 3
  names    = ["a", "b"]
  one      = "single"
  tags     = { team = "ml", env = "prod" }
  unknown  = some_function_that_does_not_exist("x")
  ref      = aws_iam_role.app.name
  refs     = [aws_iam_role.a.name, aws_iam_role.b.name, "literal"]
  data_ref = data.aws_iam_policy_document.doc.json
}
`
	if err := module.AddFile("x/main.tf", []byte(source)); err != nil {
		t.Fatal(err)
	}
	block := module.Resources("r")[0]
	attr := func(name string) *Attribute {
		a, ok := block.Attr(name)
		if !ok {
			t.Fatalf("attribute %s missing", name)
		}
		return a
	}
	if value, ok := module.Bool(attr("on")); !ok || !value {
		t.Errorf("bool = %v, %v", value, ok)
	}
	if value, ok := module.Number(attr("count_n")); !ok || value != 3 {
		t.Errorf("number = %v, %v", value, ok)
	}
	if got := module.Strings(attr("names")); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("strings = %v", got)
	}
	if got := module.Strings(attr("one")); !reflect.DeepEqual(got, []string{"single"}) {
		t.Errorf("single string = %v", got)
	}
	if got := module.StringMap(attr("tags")); got["team"] != "ml" || got["env"] != "prod" {
		t.Errorf("map = %v", got)
	}
	if keys := SortedKeys(module.StringMap(attr("tags"))); !reflect.DeepEqual(keys, []string{"env", "team"}) {
		t.Errorf("keys = %v", keys)
	}
	if _, ok := module.Text(attr("unknown")); ok {
		t.Error("an unknown function must not evaluate")
	}
	if _, ok := module.Bool(attr("one")); ok {
		t.Error("a string is not a bool")
	}
	if reference, ok := attr("ref").Reference(); !ok || reference != "aws_iam_role.app" {
		t.Errorf("reference = %q, %v", reference, ok)
	}
	if reference, ok := attr("data_ref").Reference(); !ok || reference != "data.aws_iam_policy_document.doc" {
		t.Errorf("data reference = %q, %v", reference, ok)
	}
	if got := attr("refs").References(); !reflect.DeepEqual(got, []string{"aws_iam_role.a", "aws_iam_role.b"}) {
		t.Errorf("reference list = %v", got)
	}
	if got := attr("ref").References(); !reflect.DeepEqual(got, []string{"aws_iam_role.app"}) {
		t.Errorf("single reference list = %v", got)
	}
	if _, ok := attr("one").Reference(); ok {
		t.Error("a literal is not a reference")
	}
}

func TestVariablesFromTfvarsOverrideDefaults(t *testing.T) {
	module := NewModule("x")
	files := map[string]string{
		"x/main.tf":          "variable \"region\" {\n  default = \"us-east-1\"\n}\nresource \"r\" \"t\" {\n  value = var.region\n  nodefault = var.missing\n}\n",
		"x/prod.auto.tfvars": "region = \"eu-west-1\"\n",
	}
	for name, content := range files {
		if err := module.AddFile(name, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	block := module.Resources("r")[0]
	value, _ := block.Attr("value")
	if text, ok := module.Text(value); !ok || text != "eu-west-1" {
		t.Errorf("value = %q, %v", text, ok)
	}
	missing, _ := block.Attr("nodefault")
	if text, ok := module.Text(missing); !ok || text != "<unresolved:var.missing>" {
		t.Errorf("missing = %q, %v", text, ok)
	}
}

func TestFileFunctionReadsFromModule(t *testing.T) {
	module := NewModule("x")
	if err := module.AddFile("x/main.tf", []byte("resource \"r\" \"t\" {\n  policy = file(\"${path.module}/policy.json\")\n  other = file(\"absent.json\")\n}\n")); err != nil {
		t.Fatal(err)
	}
	module.files["policy.json"] = []byte(`{"Statement": []}`)
	block := module.Resources("r")[0]
	policy, _ := block.Attr("policy")
	if text, ok := module.Text(policy); !ok || text != `{"Statement": []}` {
		t.Errorf("policy = %q, %v", text, ok)
	}
	other, _ := block.Attr("other")
	if _, ok := module.Text(other); ok {
		t.Error("a file outside the module must not evaluate")
	}
}

func TestSyntaxErrors(t *testing.T) {
	tests := []struct {
		name string
		file string
		data string
	}{
		{"broken block", "x/main.tf", "resource \"a\" {"},
		{"broken tfvars", "x/a.tfvars", "region = "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewModule("x").AddFile(tt.file, []byte(tt.data)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestBaseName(t *testing.T) {
	tests := map[string]string{"a.json": "a.json", "dir/a.json": "a.json", `dir\a.json`: "a.json", "x/y/z.tf": "z.tf"}
	for input, want := range tests {
		if got := baseName(input); got != want {
			t.Errorf("baseName(%q) = %q, want %q", input, got, want)
		}
	}
}
