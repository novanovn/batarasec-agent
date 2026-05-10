package version

var (
	Version   = "0.1.0-dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func String() string {
	return Version + " (commit: " + Commit + ", built: " + BuildTime + ")"
}
