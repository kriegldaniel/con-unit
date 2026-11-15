package conunit

import "slices"

// Parameters of the lint pack, shared with its documentation. The key lists of
// SPEC-03 are the lists of Dockle v0.4.15 (suspicious ENV keys and accepted
// keys), and the paths of FS-01 are the hygiene paths plus the apt lists that
// the hygiene pack does not carry.
var (
	lintSecretEnvKeys   = []string{"PASS", "PASSWD", "PASSWORD", "SECRET", "KEY", "ACCESS", "TOKEN"}
	lintAcceptedEnvKeys = []string{"GPG_KEY", "GPG_KEYS"}
	lintPaths           = append(slices.Clone(hygienePaths), "/var/lib/apt/lists")
)

func init() {
	// The flag names are registered here so that the pack stays in its own
	// file. rules_doc.go reads PackFlagNames, and ResolvePack resolves the same
	// names.
	PackFlagNames["PACK-IMAGE-LINT"] = []string{"lint", "image-lint"}
}

// Check constructors of the lint pack.

// staticOnly runs a check without the engine. FS-01 and FS-04 fall back to a
// container probe when the file index is missing and an engine is set. The lint
// pack is static by contract, so for it a missing index is UNVERIFIED and the
// engine is never started.
func staticOnly(check packCheck) packCheck {
	inner := check.run
	check.run = func(p *basePack, c *Container) {
		if c.OCIIndex == nil && c.Engine != nil {
			held := c.Engine
			c.Engine = nil
			defer func() { c.Engine = held }()
		}
		inner(p, c)
	}
	return check
}

func checkEnvAccepting(keys, accepted []string) packCheck {
	return packCheck{id: "SPEC-03", params: listParam("disallowed keys", keys) + "; " + listParam("accepted keys", accepted),
		run: func(_ *basePack, c *Container) { c.AssertSpec().DisallowedEnvKeysExcept(accepted, keys...) }}
}

func checkUpdateWithInstall() packCheck {
	return packCheck{id: "SPEC-09", params: "package managers: apt-get, apt", run: func(_ *basePack, c *Container) { c.AssertSpec().UpdateCombinedWithInstall() }}
}

func checkNoSudo() packCheck {
	return packCheck{id: "SPEC-10", run: func(_ *basePack, c *Container) { c.AssertSpec().NoSudoInHistory() }}
}

func checkNoDistUpgrade() packCheck {
	return packCheck{id: "SPEC-11", params: "commands: apt-get dist-upgrade, apt dist-upgrade", run: func(_ *basePack, c *Container) { c.AssertSpec().NoDistUpgradeInHistory() }}
}

func checkSensitiveVolumes() packCheck {
	return packCheck{id: "SPEC-12", params: listParam("paths", sensitiveVolumeRoots) + " and below", run: func(_ *basePack, c *Container) { c.AssertSpec().NoSensitiveVolumes() }}
}

func checkExplicitReference() packCheck {
	return packCheck{id: "SPEC-13", params: "rejected: no tag and no digest, tag latest", run: func(_ *basePack, c *Container) { c.AssertSpec().ExplicitNonLatestReference() }}
}

func checkUniqueIDs() packCheck {
	return packCheck{id: "FS-10", params: "files: /etc/passwd, /etc/group", run: func(_ *basePack, c *Container) { c.AssertFilesystem().UniqueAccountAndGroupIDs() }}
}

func checkDevelopmentLeftovers() packCheck {
	return packCheck{id: "FS-11",
		params: listParam("directories", leftoverDirNames) + "; " + listParam("files", leftoverFileNames) + "; " + listParam("skipped trees", leftoverSkipDirs),
		run:    func(_ *basePack, c *Container) { c.AssertFilesystem().NoDevelopmentLeftovers() }}
}

func checkCredentialFiles() packCheck {
	return packCheck{id: "FS-12",
		params: listParam("file names", credentialFileNames) + "; " + listParam("extensions", credentialExtensions),
		run:    func(_ *basePack, c *Container) { c.AssertFilesystem().NoCredentialNamedFiles() }}
}

// ImageLint returns the static lint pack. It runs the checks that need the image
// configuration, the build history and the file tree only, so it needs no
// container run, no engine probe and no package inventory (no Tier 3 and no
// Tier 4 check), and it works on every image source. It is the pack that
// covers the image-level checkpoints of the Dockle linter, next to the
// hardening profile.
func ImageLint() RulePack {
	return &basePack{
		id:   "PACK-IMAGE-LINT",
		name: "Image Static Lint Pack",
		description: "Static checks over the image configuration, the build history and the file tree, chosen to cover the image-level checkpoints of the Dockle linter. " +
			"The pack starts no container and needs no engine probe and no package inventory. It is a ConUnit profile and not a compliance assessment. " +
			"Its SPEC-03 uses the suspicious and accepted environment keys of Dockle v0.4.15, and its FS-01 uses the paths of the hygiene pack plus /var/lib/apt/lists. " +
			"SPEC-09 to SPEC-13, FS-10 to FS-12 are exploratory checks: their limits state where they differ from Dockle on purpose. " +
			"The names lint and image-lint resolve to this pack.",
		checks: []packCheck{
			checkUserNotRoot(),
			checkHealthcheck(),
			staticOnly(checkSuid()),
			checkCopyOverAdd(),
			checkEnvAccepting(lintSecretEnvKeys, lintAcceptedEnvKeys),
			checkPrivateKeys(),
			checkEmptyPasswords(),
			staticOnly(checkPaths(lintPaths)),
			checkUpdateWithInstall(),
			checkNoSudo(),
			checkNoDistUpgrade(),
			checkSensitiveVolumes(),
			checkExplicitReference(),
			checkUniqueIDs(),
			checkDevelopmentLeftovers(),
			checkCredentialFiles(),
		},
	}
}
