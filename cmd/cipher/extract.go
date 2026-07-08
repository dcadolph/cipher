package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/dcadolph/cipher"
)

// extractStep is one step in an --extract path: a map key or an array
// index.
type extractStep struct {
	// key is the map key when isIndex is false.
	key string
	// index is the array index when isIndex is true.
	index int
	// isIndex reports whether this step indexes an array.
	isIndex bool
}

// extractValue parses already-decrypted plain in the format inferred
// from path, walks the sops-style extract expression, and renders the
// selected node. Scalars render as their raw value; maps and slices are
// re-encoded in the file format.
func extractValue(path string, plain []byte, expr string) ([]byte, error) {
	steps, err := parseExtractPath(expr)
	if err != nil {
		return nil, err
	}

	format := cipher.FormatForPath(path)
	var root any
	switch format {
	case cipher.FormatJSON:
		if err := json.Unmarshal(plain, &root); err != nil {
			return nil, fmt.Errorf("extract: parse json: %w", err)
		}
	case cipher.FormatYAML:
		if err := yaml.Unmarshal(plain, &root); err != nil {
			return nil, fmt.Errorf("extract: parse yaml: %w", err)
		}
	default:
		return nil, fmt.Errorf(
			"extract: unsupported format for %q: need a .yaml or .json path", path)
	}

	cur := root
	for stepNum, step := range steps {
		cur, err = stepInto(cur, step)
		if err != nil {
			return nil, fmt.Errorf("extract: step %d: %w", stepNum, err)
		}
	}
	return renderExtracted(cur, format)
}

// parseExtractPath parses an expression such as `["db"]["password"]` or
// `["hosts"][0]` into ordered steps. Keys use single or double quotes;
// indexes are bare integers.
func parseExtractPath(expr string) ([]extractStep, error) {
	var steps []extractStep
	pos, end := 0, len(expr)
	for pos < end {
		for pos < end && expr[pos] == ' ' {
			pos++
		}
		if pos >= end {
			break
		}
		if expr[pos] != '[' {
			return nil, fmt.Errorf("extract: expected '[' at position %d in %q", pos, expr)
		}
		pos++
		if pos >= end {
			return nil, fmt.Errorf("extract: unterminated group in %q", expr)
		}

		if quote := expr[pos]; quote == '"' || quote == '\'' {
			pos++
			start := pos
			for pos < end && expr[pos] != quote {
				pos++
			}
			if pos >= end {
				return nil, fmt.Errorf("extract: unterminated string in %q", expr)
			}
			key := expr[start:pos]
			pos++
			if pos >= end || expr[pos] != ']' {
				return nil, fmt.Errorf("extract: expected ']' after key in %q", expr)
			}
			pos++
			steps = append(steps, extractStep{key: key})
			continue
		}

		start := pos
		for pos < end && expr[pos] != ']' {
			pos++
		}
		if pos >= end {
			return nil, fmt.Errorf("extract: unterminated index in %q", expr)
		}
		raw := strings.TrimSpace(expr[start:pos])
		idx, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("extract: bad index %q in %q", raw, expr)
		}
		pos++
		steps = append(steps, extractStep{index: idx, isIndex: true})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("extract: empty path %q", expr)
	}
	return steps, nil
}

// stepInto applies one path step to the current node, returning the
// child value or an error describing the mismatch.
func stepInto(cur any, step extractStep) (any, error) {
	if step.isIndex {
		arr, ok := cur.([]any)
		if !ok {
			return nil, fmt.Errorf("index [%d] into non-array", step.index)
		}
		if step.index < 0 || step.index >= len(arr) {
			return nil, fmt.Errorf("index [%d] out of range (len %d)", step.index, len(arr))
		}
		return arr[step.index], nil
	}
	switch m := cur.(type) {
	case map[string]any:
		value, ok := m[step.key]
		if !ok {
			return nil, fmt.Errorf("key %q not found", step.key)
		}
		return value, nil
	case map[any]any:
		value, ok := m[step.key]
		if !ok {
			return nil, fmt.Errorf("key %q not found", step.key)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("key %q into non-map", step.key)
	}
}

// renderExtracted turns the selected node into output bytes. Scalars
// become their raw value; maps and slices are re-encoded in format.
func renderExtracted(cur any, format cipher.Format) ([]byte, error) {
	if scalar, ok := scalarString(cur); ok {
		return []byte(scalar), nil
	}
	switch format {
	case cipher.FormatJSON:
		return json.Marshal(cur)
	case cipher.FormatYAML:
		return yaml.Marshal(cur)
	default:
		return nil, fmt.Errorf("extract: cannot render %T", cur)
	}
}
