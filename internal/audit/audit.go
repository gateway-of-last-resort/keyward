package audit

import (
	"time"

	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

func calcReport(results []AuditResult) (points int, grade Grade, critical, warning, info int) {
	points = 100
	for _, result := range results {
		switch result.Severity {
		case Critical:
			critical++
			points -= 20

		case Warning:
			warning++
			points -= 5

		case Info:
			info++
			points -= 1
		}
	}

	if points < 0 {
		points = 0
	}

	switch {
	case points >= 90:
		grade = GradeA
	case points >= 70:
		grade = GradeB
	case points >= 50:
		grade = GradeC
	case points >= 30:
		grade = GradeD
	default:
		grade = GradeF
	}
	return points, grade, critical, warning, info
}

// Run executes all key, config, and system checks and returns a scored AuditReport.
func Run(allKeys []keys.Key, cfg *config.Config, sshDir string) AuditReport {
	keyChecks := []KeyCheck{
		checkPassphrase,
		checkAlgorithm,
		checkBitSize,
		checkPermissions,
		checkAge,
	}

	configChecks := []ConfigCheck{
		checkStrictHostKeyChecking,
		checkIdentityFileExists,
		newCheckKeyLinkedToHost(allKeys),
		checkForwardAgent,
		checkUserKnownHostsDevNull,
	}

	systemChecks := []SystemCheck{
		newCheckSSHDirPermissions(sshDir),
		newCheckConfigPermissions(sshDir),
		checkPlatformPermissionModel,
		checkSSHAgent,
	}

	allResults := []AuditResult{}

	for _, key := range allKeys {
		for _, check := range keyChecks {
			allResults = append(allResults, check(key)...)
		}
	}

	if cfg != nil {
		for _, check := range configChecks {
			allResults = append(allResults, check(cfg)...)
		}
	}

	for _, check := range systemChecks {
		allResults = append(allResults, check()...)
	}

	points, grade, critical, warning, info := calcReport(allResults)

	return AuditReport{
		Results:       allResults,
		Points:        points,
		Grade:         grade,
		GeneratedAt:   time.Now(),
		CriticalCount: critical,
		WarningCount:  warning,
		InfoCount:     info,
	}
}
