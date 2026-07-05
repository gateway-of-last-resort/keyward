package audit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
)

func TestHasSeverity(t *testing.T) {
	report := func(sevs ...audit.Severity) audit.AuditReport {
		var r audit.AuditReport
		for _, s := range sevs {
			r.Results = append(r.Results, audit.AuditResult{Severity: s})
		}
		return r
	}

	cases := []struct {
		name    string
		report  audit.AuditReport
		fail    audit.Severity
		wantHit bool
	}{
		{"empty never trips", report(), audit.Info, false},
		{"info trips info", report(audit.Info), audit.Info, true},
		{"info does not trip warning", report(audit.Info), audit.Warning, false},
		{"critical trips warning", report(audit.Critical), audit.Warning, true},
		{"warning trips warning", report(audit.Warning), audit.Warning, true},
		{"warning does not trip critical", report(audit.Warning), audit.Critical, false},
		{"mixed trips critical", report(audit.Info, audit.Critical), audit.Critical, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.report.HasSeverity(tc.fail); got != tc.wantHit {
				t.Fatalf("HasSeverity(%s) = %v, want %v", tc.fail, got, tc.wantHit)
			}
		})
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	in := audit.AuditReport{
		Results: []audit.AuditResult{{
			KeyPath:  "/home/u/.ssh/id_rsa",
			Severity: audit.Critical,
			Category: audit.CategoryKey,
			Message:  "missing passphrase",
			Fix:      "ssh-keygen -p -f id_rsa",
		}},
		Points:        80,
		Grade:         audit.GradeB,
		CriticalCount: 1,
	}

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Stable public schema: snake_case keys and cleaned category value.
	for _, want := range []string{`"grade":"B"`, `"points":80`, `"critical_count":1`,
		`"category":"key"`, `"severity":"CRITICAL"`, `"fix":`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("json missing %q\ngot: %s", want, data)
		}
	}

	var out audit.AuditReport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].Message != "missing passphrase" {
		t.Fatalf("round-trip lost data: %+v", out)
	}
	if out.Grade != audit.GradeB || out.Points != 80 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
