package audit

import (
	"time"

	"github.com/gateway-of-last-resort/ssh-vault/internal/config"
	"github.com/gateway-of-last-resort/ssh-vault/internal/keys"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	Warning  Severity = "WARNING"
	Info     Severity = "INFO"
)

type Category string

const (
	CategoryKey    Category = "Category Key"
	CategoryConfig Category = "Category Config"
	CategorySystem Category = "Category System"
)

type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

type AuditResult struct {
	KeyPath  string
	Severity Severity
	Category Category
	Message  string
	Fix      string
}

type AuditReport struct {
	Results       []AuditResult
	Points        int
	Grade         Grade
	GeneratedAt   time.Time
	CriticalCount int
	WarningCount  int
	InfoCount     int
}

type KeyCheck func(keys.Key) []AuditResult

type ConfigCheck func(*config.Config) []AuditResult

type SystemCheck func() []AuditResult
