package terraform

import "testing"

func FuzzModule(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("locals {\n  a = local.b\n  b = local.a\n}\nresource \"r\" \"t\" {\n  v = local.a\n  w = var.x\n}\nvariable \"x\" {\n  default = var.x\n}\n"))
	f.Add([]byte("resource \"r\" \"t\" {\n  p = jsonencode({a = [for x in [1,2] : x]})\n  q = file(\"../x\")\n  r = \"${aws_x.y[0].z}\"\n}\n"))
	f.Add([]byte("resource \"a\" {"))
	f.Add([]byte("x = <<EOT\nunterminated"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		module := NewModule("fuzz")
		if err := module.AddFile("fuzz/main.tf", data); err != nil {
			return
		}
		for _, resourceType := range module.ResourceTypes() {
			for _, block := range module.Resources(resourceType) {
				for _, attribute := range block.Attrs {
					module.Text(attribute)
					module.Bool(attribute)
					module.Strings(attribute)
					module.StringMap(attribute)
					attribute.Reference()
					attribute.References()
				}
				for _, child := range block.Blocks {
					for _, attribute := range child.Attrs {
						module.Text(attribute)
					}
				}
			}
		}
	})
}
