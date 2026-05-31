package config

type TokenType int

const (
	EMPTY   TokenType = iota
	COMMENT TokenType = iota
	HOST    TokenType = iota
	MATCH   TokenType = iota
	PARAM   TokenType = iota
)

type ValidationLevel int

const (
	LevelWarning ValidationLevel = iota
	LevelError
)

type Token struct {
	Type    TokenType
	Key     string // for PARAM/HOST/MATCH
	Value   string // for PARAM/HOST/MATCH
	Sep     string // " " or "="
	Raw     string // original str for raw data
	LineNum int    // for errors
}
type Block struct {
	IsGlobal bool    // true for everything before first Host
	Pattern  string  // everything after Host/Match
	IsMatch  bool    // diff Match from Host
	Tokens   []Token // all lines including empty and comments
}
type Config struct {
	Path     string
	Global   Block
	Blocks   []Block
	Modified bool
	Original []byte
}

type ValidationResult struct {
	Block   *Block
	Line    int
	Field   string
	Message string
	Level   ValidationLevel
}

type ParamResult struct {
	Value string
	Line  int
}
