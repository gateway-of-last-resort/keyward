package config

import (
	"bytes"
	"os"
	"strings"
)

// hasKeyword reports whether the lowercased, trimmed line begins with keyword
// followed by a keyword/argument separator. ssh_config(5) separates a keyword
// from its argument with whitespace or optional-whitespace + '=', so "Host\tx",
// "Host x", and "Host=x" are all valid block starts.
func hasKeyword(lower, keyword string) bool {
	if !strings.HasPrefix(lower, keyword) {
		return false
	}
	rest := lower[len(keyword):]
	return len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t' || rest[0] == '=')
}

// keywordArg returns the argument following a keyword of the given length,
// accepting either whitespace or a single '=' (with optional surrounding
// whitespace) as the separator per ssh_config(5). So "Host = x", "Host=x", and
// "Host x" all yield "x".
func keywordArg(trimmed string, keywordLen int) string {
	rest := strings.TrimLeft(trimmed[keywordLen:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return strings.TrimSpace(rest)
}

func parseParam(raw string) Token {
	t := Token{Type: PARAM, Raw: raw}
	trimmed := strings.TrimSpace(raw)

	// The key runs up to the first separator character: whitespace or '='.
	sepStart := strings.IndexAny(trimmed, " \t=")
	if sepStart == -1 {
		t.Key = trimmed
		t.Sep = " "
		return t
	}
	t.Key = trimmed[:sepStart]

	// ssh_config(5): the argument is separated by whitespace, or by optional
	// whitespace + a single '=' + optional whitespace. Detect which so an edited
	// line re-serialises in the same style, and so a '=' inside the value (e.g. an
	// option string) is not mistaken for the separator.
	rest := strings.TrimLeft(trimmed[sepStart:], " \t")
	if strings.HasPrefix(rest, "=") {
		t.Sep = "="
		rest = strings.TrimLeft(rest[1:], " \t")
	} else {
		t.Sep = " "
	}
	t.Value = strings.TrimSpace(rest)
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
				tokens[i].Type = HOST
				tokens[i].Key = trimmed[:len("host")]
				tokens[i].Value = keywordArg(trimmed, len("host"))
				tokens[i].Sep = " "
			} else if hasKeyword(lower, "match") {
				tokens[i].Type = MATCH
				tokens[i].Key = trimmed[:len("match")]
				tokens[i].Value = keywordArg(trimmed, len("match"))
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
	var seenHost bool

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
