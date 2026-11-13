package iac

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

type pair struct {
	key   *yaml.Node
	value *yaml.Node
}

func decodeDocuments(data []byte) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var roots []*yaml.Node
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return roots, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode yaml: %w", err)
		}
		if document.Kind == yaml.DocumentNode && len(document.Content) == 1 {
			roots = append(roots, resolve(document.Content[0]))
		}
	}
}

func resolve(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

func pairs(node *yaml.Node) []pair {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var out []pair
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], resolve(node.Content[i+1])
		if key.Value == "<<" {
			out = append(out, pairs(value)...)
			continue
		}
		out = append(out, pair{key: key, value: value})
	}
	return out
}

func get(node *yaml.Node, key string) *yaml.Node {
	for _, entry := range pairs(node) {
		if entry.key.Value == key {
			return entry.value
		}
	}
	return nil
}

func items(node *yaml.Node) []*yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(node.Content))
	for _, child := range node.Content {
		out = append(out, resolve(child))
	}
	return out
}

func scalar(node *yaml.Node) string {
	node = resolve(node)
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return ""
	}
	return node.Value
}

func isNull(node *yaml.Node) bool {
	node = resolve(node)
	return node == nil || (node.Kind == yaml.ScalarNode && node.Tag == "!!null")
}
