package conunit

// envKeyAccepted reports whether an environment variable name is on the list
// of accepted keys of SPEC-03. The comparison is exact and keeps the case: the
// list names variables, not patterns, so GPG_KEY accepts GPG_KEY and neither
// gpg_key nor MY_GPG_KEY.
func envKeyAccepted(key string, accepted []string) bool {
	for _, name := range accepted {
		if key == name {
			return true
		}
	}
	return false
}
