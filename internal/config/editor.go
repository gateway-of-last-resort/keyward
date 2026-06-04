package config

import (
	"slices"
	"strings"
)

func findBlockIdx(c *Config, pattern string) int {
	idx := -1
	for i := range c.Blocks {
		if c.Blocks[i].Pattern == pattern {
			idx = i
			break
		}
	}
	return idx
}

func serializeBlock(b *Block) string {
	var sb strings.Builder
	for _, token := range b.Tokens {
		sb.WriteString(token.Raw)
		sb.WriteString("\n")
	}
	return sb.String()
}

func FindBlock(c *Config, pattern string) *Block {
	for i := range c.Blocks {
		if strings.EqualFold(c.Blocks[i].Pattern, pattern) {
			return &c.Blocks[i]
		}
	}
	return nil
}

func AddBlock(c *Config, pattern string) {
	hostToken := Token{
		Type:  HOST,
		Key:   "Host",
		Sep:   " ",
		Value: pattern,
	}
	hostBlock := Block{
		Pattern: pattern,
		Tokens:  []Token{hostToken},
	}

	c.Blocks = append(c.Blocks, hostBlock)
	c.Modified = true
}

func RemoveBlock(c *Config, pattern string) bool {

	idx := findBlockIdx(c, pattern)

	if idx != -1 {
		c.Blocks = slices.Delete(c.Blocks, idx, idx+1)
		c.Modified = true
		return true
	}
	return false
}

func DuplicateBlock(c *Config, pattern, newPattern string) bool {

	idx := findBlockIdx(c, pattern)

	if idx != -1 {
		newBlock := c.Blocks[idx]
		newBlock.Tokens = append([]Token{}, c.Blocks[idx].Tokens...)
		newBlock.Pattern = newPattern
		for i := range newBlock.Tokens {
			if newBlock.Tokens[i].Type == HOST {
				newBlock.Tokens[i].Value = newPattern
				newBlock.Tokens[i].Raw = ""
			}
		}
		c.Blocks = append(c.Blocks, newBlock)
		c.Modified = true

		return true
	}

	return false
}

func MoveBlock(c *Config, pattern string, toIdx int) bool {

	idx := findBlockIdx(c, pattern)

	if toIdx < 0 {
		toIdx = 0
	}
	if toIdx > len(c.Blocks)-1 {
		toIdx = len(c.Blocks) - 1
	}

	if idx != -1 {
		movedBlock := c.Blocks[idx]
		c.Blocks = slices.Delete(c.Blocks, idx, idx+1)
		c.Blocks = slices.Insert(c.Blocks, toIdx, movedBlock)
		c.Modified = true

		return true
	}

	return false
}

func Search(c *Config, query string) []*Block {

	found := []*Block{}

	for i := range c.Blocks {
		matched := false

		if strings.Contains(strings.ToLower(c.Blocks[i].Pattern), strings.ToLower(query)) {
			matched = true
		}
		if !matched {

			hosts, hostFound := GetParam(&c.Blocks[i], "HostName")

			if hostFound {
				for _, host := range hosts {
					if strings.Contains(strings.ToLower(host), strings.ToLower(query)) {
						matched = true
					}
				}
			}
		}
		if !matched {
			users, userFound := GetParam(&c.Blocks[i], "User")

			if userFound {
				for _, user := range users {
					if strings.Contains(strings.ToLower(user), strings.ToLower(query)) {
						matched = true
					}
				}
			}
		}

		if matched {
			found = append(found, &c.Blocks[i])
		}

	}
	return found
}

func Reset(c *Config) {
	fresh := ParseBytes(c.Path, c.Original)
	*c = fresh
}

// TODO: improve to a line-by-line diff with --- / +++ format,
// currently only tracks added, removed and modified blocks by pattern

func Diff(c *Config) []string {
	original := ParseBytes(c.Path, c.Original)

	originalMap := make(map[string]string, len(original.Blocks))
	for i := range original.Blocks {
		originalMap[original.Blocks[i].Pattern] = serializeBlock(&original.Blocks[i])
	}

	currentMap := make(map[string]string, len(c.Blocks))
	for i := range c.Blocks {
		currentMap[c.Blocks[i].Pattern] = serializeBlock(&c.Blocks[i])
	}

	var changes []string

	for pattern, current := range currentMap {
		if orig, exists := originalMap[pattern]; !exists {
			changes = append(changes, "added: "+pattern)
		} else if orig != current {
			changes = append(changes, "modified: "+pattern)
		}
	}

	for pattern := range originalMap {
		if _, exists := currentMap[pattern]; !exists {
			changes = append(changes, "removed: "+pattern)
		}
	}

	return changes
}
