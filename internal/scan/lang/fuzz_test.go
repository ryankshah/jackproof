package lang

import "testing"

func FuzzExtract(f *testing.F) {
	f.Add(uint8(0), []byte("package main\nimport (\"log\"; \"os\")\nfunc main() { k := os.Getenv(\"OPENAI_API_KEY\"); log.Println(k) }\n"))
	f.Add(uint8(1), []byte("import os\nk = os.environ[\"OPENAI_API_KEY\"]\nprint(k)\nclient.get_secret_value(SecretId='x')\n"))
	f.Add(uint8(2), []byte("const k = process.env.OPENAI_API_KEY;\nconsole.log(k);\nnew OpenAI({apiKey: k});\n"))
	f.Add(uint8(0), []byte("package"))
	f.Add(uint8(1), []byte("k = ("))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		extractor, err := New(func(name string) bool { return name == "OPENAI_API_KEY" })
		if err != nil {
			t.Fatal(err)
		}
		languages := []string{Go, Python, JavaScript}
		facts, err := extractor.Extract(languages[int(kind)%len(languages)], data)
		if err != nil {
			return
		}
		for _, leak := range facts.Leaks {
			if leak.Line < 1 {
				t.Fatalf("a leak has line %d", leak.Line)
			}
		}
		for _, lookup := range facts.SecretLookups {
			if lookup.Name == "" || lookup.Line < 1 {
				t.Fatalf("bad lookup %+v", lookup)
			}
		}
	})
}
