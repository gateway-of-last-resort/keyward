package audit

import (
	"time"

	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
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
	CategoryKey    Category = "key"
	CategoryConfig Category = "config"
	CategorySystem Category = "system"
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
	KeyPath  string   `json:"key_path,omitempty"`
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// AuditReport is the aggregated result of a full audit run.
type AuditReport struct {
	Results       []AuditResult `json:"results"`
	Points        int           `json:"points"`
	Grade         Grade         `json:"grade"`
	GeneratedAt   time.Time     `json:"generated_at"`
	CriticalCount int           `json:"critical_count"`
	WarningCount  int           `json:"warning_count"`
	InfoCount     int           `json:"info_count"`
}

// severityRank orders severities so findings can be compared against a
// threshold. Higher is more severe; unknown severities rank 0.
func severityRank(s Severity) int {
	switch s {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// HasSeverity reports whether the report contains any finding at or above sev.
// It backs the CLI's --fail-on threshold for CI use.
func (r AuditReport) HasSeverity(sev Severity) bool {
	threshold := severityRank(sev)
	if threshold == 0 {
		return false
	}
	for _, res := range r.Results {
		if severityRank(res.Severity) >= threshold {
			return true
		}
	}
	return false
}

// KeyCheck is a check function that inspects a single SSH key.
type KeyCheck func(keys.Key) []AuditResult

// ConfigCheck is a check function that inspects the SSH config.
type ConfigCheck func(*config.Config) []AuditResult

// SystemCheck is a check function that inspects the host environment.
type SystemCheck func() []AuditResult
