package config

import (
	"bytes"
	"os"
	"strings"
)

// hasKeyword reports whether the lowercased, trimmed line begins with keyword
// followed by whitespace (space or tab). ssh_config(5) allows any whitespace
// as the separator, so "Host\tgithub.com" is as valid as "Host github.com".
func hasKeyword(lower, keyword string) bool {
	if !strings.HasPrefix(lower, keyword) {
		return false
	}
	rest := lower[len(keyword):]
	return len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t')
}

func parseParam(raw string) Token {
	var t Token
	t.Type = PARAM
	t.Raw = raw

	trimmed := strings.TrimSpace(t.Raw)

	eqIdx := strings.Index(trimmed, "=")
	// Any whitespace separates a key from its value, not just a literal space.
	wsIdx := strings.IndexAny(trimmed, " \t")
	var sepIdx int
	var hasSep bool

	switch {
	case eqIdx == -1 && wsIdx == -1:
		t.Key = trimmed
		t.Sep = " "

	case eqIdx == -1:
		sepIdx, hasSep = wsIdx, true
		t.Sep = " "

	case wsIdx == -1:
		sepIdx, hasSep = eqIdx, true
		t.Sep = "="

	case eqIdx < wsIdx:
		sepIdx, hasSep = eqIdx, true
		t.Sep = "="

	default:
		sepIdx, hasSep = wsIdx, true
		t.Sep = " "
	}

	if hasSep {
		t.Key = strings.TrimSpace(trimmed[:sepIdx])
		t.Value = strings.TrimSpace(trimmed[sepIdx+1:])
	}

	return t
}

func tokenize(data []byte) []Token {
	lines := bytes.Split(data, []byte("\n"))
	tokens := make([]Token, len(lines))

	for i, line := range lines {
		tokens[i].LineNum = i + 1
		raw := string(line)
		raw = strings.TrimRight(raw, "\r")
		tokens[i].Raw = raw

		trimmed := strings.TrimSpace(raw)

		if trimmed == "" {
			tokens[i].Type = EMPTY
		} else if strings.HasPrefix(trimmed, "#") {
			tokens[i].Type = COMMENT
		} else {
			lower := strings.ToLower(trimmed)
			if hasKeyword(lower, "host") {
				value := strings.TrimSpace(trimmed[len("host"):])
				tokens[i].Type = HOST
				tokens[i].Key = trimmed[:len("host")]
				tokens[i].Value = value
				tokens[i].Sep = " "
			} else if hasKeyword(lower, "match") {
				value := strings.TrimSpace(trimmed[len("match"):])
				tokens[i].Type = MATCH
				tokens[i].Key = trimmed[:len("match")]
				tokens[i].Value = value
				tokens[i].Sep = " "
			} else {
				tokens[i] = parseParam(raw)
				tokens[i].LineNum = i + 1
			}
		}
	}
	return tokens
}

func group(tokens []Token) (Block, []Block) {

	var global Block
	global.IsGlobal = true

	var blocks []Block
	var current *Block = nil
	var pending []Token
	var seenHost bool = false

	for _, token := range tokens {

		switch token.Type {
		case EMPTY, COMMENT:
			pending = append(pending, token)

		case HOST, MATCH:
			if current != nil {
				blocks = append(blocks, *current)
			}
			newBlock := Block{}
			newBlock.IsMatch = token.Type == MATCH
			newBlock.Pattern = token.Value
			newBlock.Tokens = append(newBlock.Tokens, pending...)
			newBlock.Tokens = append(newBlock.Tokens, token)
			current = &newBlock
			pending = pending[:0]
			seenHost = true

		case PARAM:
			if !seenHost {
				global.Tokens = append(global.Tokens, pending...)
				global.Tokens = append(global.Tokens, token)
			} else {
				current.Tokens = append(current.Tokens, pending...)
				current.Tokens = append(current.Tokens, token)
			}
			pending = pending[:0]
		}
	}

	if current != nil {
		current.Tokens = append(current.Tokens, pending...)
		blocks = append(blocks, *current)
	} else if len(pending) > 0 {
		global.Tokens = append(global.Tokens, pending...)
	}

	return global, blocks
}

// ParseBytes parses an SSH config from data and associates it with path.
func ParseBytes(path string, data []byte) Config {
	tokens := tokenize(data)
	global, blocks := group(tokens)

	return Config{
		Path:     path,
		Global:   global,
		Blocks:   blocks,
		Modified: false,
		Original: bytes.Clone(data),
	}
}

// ParseFile reads path from disk and parses it as an SSH config.
func ParseFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseBytes(path, data), nil
}
