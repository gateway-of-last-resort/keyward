package config

import (
	"slices"
	"strings"
)

// GetParam returns all values for key in b (case-insensitive). A key may appear more than once.
func GetParam(b *Block, key string) ([]string, bool) {
	var values []string

	for _, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			values = append(values, token.Value)
		}
	}

	return values, len(values) > 0
}

// GetParamWithLine is like GetParam but also returns the line number of each occurrence.
func GetParamWithLine(b *Block, key string) ([]ParamResult, bool) {
	var values []ParamResult

	for _, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			values = append(values, ParamResult{Value: token.Value, Line: token.LineNum})
		}
	}

	return values, len(values) > 0
}

// SetParam updates existing key tokens with values, inserting or removing tokens as needed.
func SetParam(b *Block, key string, values []string) bool {
	var indices []int

	for i, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			indices = append(indices, i)
		}
	}

	if len(indices) == 0 {
		return false
	}

	n := min(len(indices), len(values))

	for i := 0; i < n; i++ {
		b.Tokens[indices[i]].Value = sanitize(values[i])
		b.Tokens[indices[i]].Raw = ""
	}

	if len(values) > len(indices) {
		insertAt := indices[len(indices)-1] + 1
		for i := len(indices); i < len(values); i++ {
			newToken := Token{
				Type:  PARAM,
				Key:   key,
				Value: sanitize(values[i]),
				Sep:   " ",
				Raw:   "",
			}
			b.Tokens = slices.Insert(b.Tokens, insertAt, newToken)
			insertAt++
		}
	}
	if len(indices) > len(values) {
		for i := len(indices) - 1; i >= len(values); i-- {
			b.Tokens = slices.Delete(b.Tokens, indices[i], indices[i]+1)
		}
	}

	return true
}

// RemoveParam removes the first occurrence of key from b.
// Note: a key may appear multiple times in a valid SSH config (e.g. IdentityFile); only the first is removed.
func RemoveParam(b *Block, key string) bool {

	for i, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			b.Tokens = slices.Delete(b.Tokens, i, i+1)
			return true
		}
	}
	return false
}

// AddParam appends a new key/value token after the last existing parameter in b.
func AddParam(b *Block, key string, value string) {
	var idx int

	for i := len(b.Tokens) - 1; i >= 0; i-- {
		if b.Tokens[i].Type == PARAM {
			idx = i + 1
			break
		} else if b.Tokens[i].Type == HOST || b.Tokens[i].Type == MATCH {
			idx = i + 1
			break
		}
	}

	newToken := Token{
		Type:  PARAM,
		Key:   key,
		Value: sanitize(value),
		Sep:   " ",
	}
	b.Tokens = slices.Insert(b.Tokens, idx, newToken)

}

// RemoveParamAt removes the token at index idx from b.Tokens.
func RemoveParamAt(b *Block, idx int) {
	if idx < 0 || idx >= len(b.Tokens) {
		return
	}
	b.Tokens = slices.Delete(b.Tokens, idx, idx+1)
}

// RenameHost updates the Host token value and b.Pattern to pattern.
func RenameHost(b *Block, pattern string) {

	pattern = sanitize(pattern)
	for i := range b.Tokens {
		if b.Tokens[i].Type == HOST {
			b.Tokens[i].Value = pattern
			b.Tokens[i].Raw = ""
			break
		}
	}
	b.Pattern = pattern
}

// ToggleLine comments out a PARAM line or restores a COMMENT line back to PARAM.
// Returns false if the line cannot be toggled (HOST, MATCH, EMPTY, or unparseable comment).
func ToggleLine(b *Block, lineNum int) bool {
	for i := range b.Tokens {
		if b.Tokens[i].LineNum == lineNum {
			return toggleAt(b, i)
		}
	}
	return false
}

// ToggleAt toggles the token at index idx (0-based into b.Tokens).
// Returns false if the token cannot be toggled.
func ToggleAt(b *Block, idx int) bool {
	if idx < 0 || idx >= len(b.Tokens) {
		return false
	}
	return toggleAt(b, idx)
}

func toggleAt(b *Block, i int) bool {
	if b.Tokens[i].Type == HOST || b.Tokens[i].Type == MATCH || b.Tokens[i].Type == EMPTY {
		return false
	}
	if b.Tokens[i].Type == PARAM {
		raw := b.Tokens[i].Raw
		if raw == "" {
			raw = b.Tokens[i].Key + b.Tokens[i].Sep + b.Tokens[i].Value
		}
		b.Tokens[i].Raw = "# " + raw
		b.Tokens[i].Type = COMMENT
		b.Tokens[i].Value = ""
		b.Tokens[i].Sep = ""
		b.Tokens[i].Key = ""
		return true
	}

	original := b.Tokens[i]
	raw := b.Tokens[i].Raw
	trimmedLeft := strings.TrimLeft(raw, " \t")
	leading := raw[:len(raw)-len(trimmedLeft)]

	var content string
	if strings.HasPrefix(trimmedLeft, "# ") {
		content = trimmedLeft[2:]
	} else if strings.HasPrefix(trimmedLeft, "#") {
		content = trimmedLeft[1:]
	} else {
		content = trimmedLeft
	}

	stripped := leading + content
	newToken := parseParam(stripped)

	if newToken.Key == "" || !isValidSSHKeyword(newToken.Key) {
		b.Tokens[i] = original
		return false
	}

	b.Tokens[i].Raw = stripped
	b.Tokens[i].Key = newToken.Key
	b.Tokens[i].Sep = newToken.Sep
	b.Tokens[i].Value = newToken.Value
	b.Tokens[i].Type = PARAM
	return true
}
