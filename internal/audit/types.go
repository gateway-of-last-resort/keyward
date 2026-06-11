package audit

import (
	"time"

	"github.com/gateway-of-last-resort/ssh-vault/internal/config"
	"github.com/gateway-of-last-resort/ssh-vault/internal/keys"
)

// Severity indicates the risk level of an audit finding.
type Severity string

const (
	Critical Severity = "CRITICAL"
	Warning  Severity = "WARNING"
	Info     Severity = "INFO"
)

// Category groups audit findings by the subsystem they relate to.
type Category string

const (
	CategoryKey    Category = "Category Key"
	CategoryConfig Category = "Category Config"
	CategorySystem Category = "Category System"
)

// Grade is the letter score assigned to an AuditReport (A–F).
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

// AuditResult is a single finding produced by a check function.
type AuditResult struct {
	KeyPath  string
	Severity Severity
	Category Category
	Message  string
	Fix      string
}

// AuditReport is the aggregated result of a full audit run.
type AuditReport struct {
	Results       []AuditResult
	Points        int
	Grade         Grade
	GeneratedAt   time.Time
	CriticalCount int
	WarningCount  int
	InfoCount     int
}

// KeyCheck is a check function that inspects a single SSH key.
type KeyCheck func(keys.Key) []AuditResult

// ConfigCheck is a check function that inspects the SSH config.
type ConfigCheck func(*config.Config) []AuditResult

// SystemCheck is a check function that inspects the host environment.
type SystemCheck func() []AuditResult
