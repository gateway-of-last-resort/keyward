package config

import (
	"slices"
	"strings"
)

func GetParam(b *Block, key string) ([]string, bool) {
	var values []string

	for _, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			values = append(values, token.Value)
		}
	}

	return values, len(values) > 0
}

func GetParamWithLine(b *Block, key string) ([]ParamResult, bool) {
	var values []ParamResult

	for _, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			values = append(values, ParamResult{Value: token.Value, Line: token.LineNum})
		}
	}

	return values, len(values) > 0
}

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
		b.Tokens[indices[i]].Value = values[i]
	}

	if len(values) > len(indices) {
		insertAt := indices[len(indices)-1] + 1
		for i := len(indices); i < len(values); i++ {
			newToken := Token{
				Type:  PARAM,
				Key:   key,
				Value: values[i],
				Sep:   " ",
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

func RemoveParam(b *Block, key string) bool {

	for i, token := range b.Tokens {
		if token.Type == PARAM && strings.EqualFold(key, token.Key) {
			b.Tokens = slices.Delete(b.Tokens, i, i+1)
			return true
		}
	}
	return false
}

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
		Value: value,
		Sep:   " ",
	}
	b.Tokens = slices.Insert(b.Tokens, idx, newToken)

}

func RenameHost(b *Block, pattern string) {

	for i := range b.Tokens {
		if b.Tokens[i].Type == HOST {
			b.Tokens[i].Value = pattern
			b.Tokens[i].Raw = ""
			break
		}
	}
	b.Pattern = pattern
}

func ToggleLine(b *Block, lineNum int) bool {

	for i := range b.Tokens {

		if b.Tokens[i].LineNum == lineNum {
			if b.Tokens[i].Type == HOST || b.Tokens[i].Type == MATCH || b.Tokens[i].Type == EMPTY {
				return false
			}
			if b.Tokens[i].Type == PARAM {
				b.Tokens[i].Type = COMMENT
				b.Tokens[i].Raw = "#" + b.Tokens[i].Raw
				b.Tokens[i].Value = ""
				b.Tokens[i].Sep = ""
				b.Tokens[i].Key = ""

				return true
			} else {
				b.Tokens[i].Raw = strings.TrimPrefix(b.Tokens[i].Raw, "# ")
				b.Tokens[i].Raw = strings.TrimPrefix(b.Tokens[i].Raw, "#")
				newToken := parseParam(b.Tokens[i].Raw)

				b.Tokens[i].Key = newToken.Key
				b.Tokens[i].Sep = newToken.Sep
				b.Tokens[i].Value = newToken.Value
				b.Tokens[i].Type = newToken.Type

				return true
			}
		}
	}
	return false
}
