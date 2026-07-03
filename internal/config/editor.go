package config

import (
	"slices"
	"strings"
)

func findBlockIdx(c *Config, pattern string) int {
	idx := -1
	for i := range c.Blocks {
		// Host patterns are matched case-sensitively (OpenSSH semantics), the
		// same way duplicate detection compares them — so "Foo" and "foo" are
		// distinct blocks and edits never target the wrong one.
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

// FindBlock returns a pointer to the block whose pattern matches exactly
// (case-sensitive, per OpenSSH), or nil.
func FindBlock(c *Config, pattern string) *Block {
	for i := range c.Blocks {
		if c.Blocks[i].Pattern == pattern {
			return &c.Blocks[i]
		}
	}
	return nil
}

// AddBlock appends a new Host block with the given pattern and sets Modified.
func AddBlock(c *Config, pattern string) {
	pattern = sanitize(pattern)
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

// RemoveBlock deletes the block matching pattern and sets Modified. Returns false if not found.
func RemoveBlock(c *Config, pattern string) bool {

	idx := findBlockIdx(c, pattern)

	if idx != -1 {
		c.Blocks = slices.Delete(c.Blocks, idx, idx+1)
		c.Modified = true
		return true
	}
	return false
}

// DuplicateBlock copies the block matching pattern to a new block with newPattern.
func DuplicateBlock(c *Config, pattern, newPattern string) bool {

	idx := findBlockIdx(c, pattern)

	if idx != -1 {
		newPattern = sanitize(newPattern)
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

// MoveBlock repositions the block matching pattern to toIdx (clamped to valid range).
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

// Search returns blocks whose Pattern, HostName, or User contains query (case-insensitive).
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

// Reset restores c to the state captured in c.Original without re-reading the file.
func Reset(c *Config) {
	fresh := ParseBytes(c.Path, c.Original)
	*c = fresh
}

// TODO: improve to a line-by-line diff with --- / +++ format,
// currently only tracks added, removed and modified blocks by pattern

// Diff returns a list of added/modified/removed block patterns relative to c.Original.
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
