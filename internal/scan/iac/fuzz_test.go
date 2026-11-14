package iac

import "testing"

func FuzzParsers(f *testing.F) {
	f.Add([]byte("services:\n  api:\n    environment:\n      OPENAI_API_KEY: ${OPENAI_API_KEY}\n    env_file: [.env]\n"))
	f.Add([]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          env:\n            - name: K\n              valueFrom:\n                secretKeyRef: {name: s, key: k}\n"))
	f.Add([]byte("on: pull_request_target\njobs:\n  j:\n    steps:\n      - run: |\n          printenv\n        env:\n          A: ${{ secrets.A }}\n"))
	f.Add([]byte("FROM x\nARG A=1\nENV B=$A C=\"two words\" \\\n  D=3\nCOPY .env /app/\n"))
	f.Add([]byte("{\n  // comment\n  \"containerEnv\": {\"A\": \"${localEnv:A}\"},\n  \"runArgs\": [\"--env-file\", \".env\"],\n}\n"))
	f.Add([]byte("A=1\nexport B=\"2\"\n# c\nC='3' # d\n"))
	f.Add([]byte("a: &x {b: 1}\nc:\n  <<: *x\n  d: *x\n"))
	f.Add([]byte("[[[[{{{{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCompose("compose.yaml", data)
		_, _ = ParseKubernetes("k8s.yaml", data)
		_, _ = ParseActions("wf.yml", data)
		ParseDockerfile("Dockerfile", data)
		_, _ = ParseDevcontainer("devcontainer.json", data)
		for _, entry := range ParseDotenv(data) {
			entry.EnvVar("env-file")
		}
		IsKubernetes(data)
		ClassifyValue(string(data))
		LooksUntrusted(string(data))
	})
}
