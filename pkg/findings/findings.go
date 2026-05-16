package findings

// Finding is the canonical vulnerability match sent to the platform.
type Finding struct {
	PackageName string  `json:"package_name"`
	Version     string  `json:"version"`
	Ecosystem   string  `json:"ecosystem"` // npm | go | python
	FilePath    string  `json:"file_path"`
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	CVSSScore   float64 `json:"cvss_score,omitempty"`
	FixedIn     string  `json:"fixed_in,omitempty"`
	Title       string  `json:"title,omitempty"`
}

// PostureFinding is a hardening/configuration finding.
type PostureFinding struct {
	RuleID      string                 `json:"rule_id"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"` // critical | high | medium | low | info
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}
