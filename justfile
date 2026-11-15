# ConUnit - Justfile for Automated Reproducible Workflows

# Default target
default:
	@just --list

# Build the con-unit binary
build:
	@mkdir -p bin
	@go build -o bin/con-unit ./cmd/con-unit
	@printf 'Built CLI: %s\n' 'bin/con-unit'

# Run offline-safe unit tests without module downloads
test:
	GOPROXY=off GOSUMDB=off go test -v ./...

# Run engine-backed tests that may pull images; requires explicit opt-in
test-integration:
	CONUNIT_INTEGRATION=1 GOPROXY=off GOSUMDB=off go test -v ./...

# Probe the real host environment detection (engine, kernel, virtualization)
test-runenv-live:
	CONUNIT_RUNENV_LIVE=1 GOPROXY=off GOSUMDB=off go test -run TestDetectLive -v ./pkg/runenv

# Run unit tests with coverage profile
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Run con-unit test on a single container image with chosen hardening profile pack
test-image image="alpine:latest" pack="cis":
	@mkdir -p bin
	@go build -o bin/con-unit ./cmd/con-unit
	@./bin/con-unit test {{image}} --pack {{pack}} --format console

# Run con-unit and generate JUnit XML
test-junit image="alpine:latest" pack="cis" output="reports/junit.xml":
	@mkdir -p bin reports
	@go build -o bin/con-unit ./cmd/con-unit
	@./bin/con-unit test {{image}} --pack {{pack}} --format junit --output {{output}}

# ---------------------------------------------------------------------------
# Evaluation. `eval` exits 0 when every image produced a COMPLETED record,
# whatever the findings, and 3 when any image ended in another status.
# Pass extra con-unit flags through `extra`, for example "--platform linux/amd64".
# ---------------------------------------------------------------------------

# Run empirical evaluation over a batch of images
eval images_file="fixtures/sample_images.txt" pack="cis" out_dir="results" extra="":
	@mkdir -p bin {{out_dir}}
	@go build -o bin/con-unit ./cmd/con-unit
	@./bin/con-unit eval --images {{images_file}} --pack {{pack}} --out-dir {{out_dir}} {{extra}}

# Run the 10 curated representative images (digest-pinned, derived from the main pin run)
eval-top10 pack="cis" out_dir="results" extra="":
	@just eval fixtures/evaluation_dataset_top10_pinned.txt {{pack}} {{out_dir}} "{{extra}}"

# Run the full digest-pinned dataset (all entries of fixtures/evaluation_dataset_pinned.txt)
eval-full pack="cis" out_dir="results" extra="":
	@just eval fixtures/evaluation_dataset_pinned.txt {{pack}} {{out_dir}} "{{extra}}"

# Pin dataset references to immutable digests (network, at most once per 6 hours)
pin-dataset frame_commit frame_date:
	@go run ./tools/pin_dataset -frame-commit {{frame_commit}} -frame-date {{frame_date}}

# Rebuild the dataset audit file offline, for example to record the sampling frame
audit-dataset frame_commit frame_date:
	@go run ./tools/pin_dataset -audit-only -frame-commit {{frame_commit}} -frame-date {{frame_date}}

# HEAD-check every pinned digest on the ECR Public mirror (paced, writes mirror_check.json)
check-mirror out_dir="results" dataset="fixtures/evaluation_dataset_pinned.txt":
	@mkdir -p {{out_dir}}
	@OUT_DIR={{out_dir}} ./tools/check_mirror.sh {{dataset}}

# Run the defect-seeded RQ1 detection benchmark (needs podman, hadolint, trivy, container-structure-test and dockle, all in the dev shell)
eval-rq1 out_dir="results" extra="":
	@mkdir -p bin {{out_dir}}/rq1
	@go build -o bin/con-unit ./cmd/con-unit
	@go run ./tools/rq1 -oracle fixtures/rq1/oracle.json -out-dir {{out_dir}}/rq1 -conunit bin/con-unit {{extra}}

# Re-classify existing RQ1 raw outputs offline
eval-rq1-analyze out_dir="results":
	@go run ./tools/rq1 -analyze-only -oracle fixtures/rq1/oracle.json -out-dir {{out_dir}}/rq1

# Run the repeated RQ3 performance benchmark (one warm-up, then timed trials)
eval-rq3 file="fixtures/evaluation_dataset_top10_pinned.txt" pack="cis" out_dir="results" iterations="10" extra="":
	@mkdir -p {{out_dir}}
	@go run ./tools/benchmark_rq3 -file {{file}} -pack {{pack}} -out-dir {{out_dir}} -iterations {{iterations}} -warmup 1 -archetypes fixtures/archetypes.json {{extra}}

# Attribute EXEC failures by controlled re-runs (run right after eval, images must be in the local store)
attribute-exec out_dir="results":
	@go run ./tools/attribute_exec -out-dir {{out_dir}} {{out_dir}}/empirical_study.json

# Export the LaTeX tables, figures and macros of a study (paper_dir writes into <paper_dir>/results/)
export-latex study="results/empirical_study.json" paper_dir="":
	@go run ./tools/export_latex.go -audit fixtures/evaluation_dataset_audit.json {{ if paper_dir != "" { "-paper-dir " + paper_dir } else { "" } }} {{study}}

# Verify that the generated files on disk equal what the exporter would produce
export-latex-check study="results/empirical_study.json" paper_dir="":
	@go run ./tools/export_latex.go -check -audit fixtures/evaluation_dataset_audit.json {{ if paper_dir != "" { "-paper-dir " + paper_dir } else { "" } }} {{study}}

# Verify scientific evaluation integrity guardrails
verify-integrity out_dir="results":
	@./tools/verify_eval_integrity.sh {{out_dir}}

# Strict integrity check for the final run (warnings fail, results required)
verify-integrity-final out_dir="results":
	@INTEGRITY_STRICT=1 REQUIRE_RESULTS=1 ./tools/verify_eval_integrity.sh {{out_dir}}

# Create the two-rater adjudication template from a study
adjudication-export study="results/empirical_study.json" sample="30":
	@go run ./tools/adjudication export -study {{study}} -exec-sample {{sample}}

# Score a completed adjudication sheet (kappa and precision per check)
adjudication-score csv="results/adjudication.csv":
	@go run ./tools/adjudication score -csv {{csv}}

# Compare two runs per check (percent agreement and kappa)
agreement a b out_dir="results":
	@go run ./tools/agreement -a {{a}} -b {{b}} -headline fixtures/headline_checks.json -out-dir {{out_dir}}

# Open an HTML dashboard from existing results without rerunning the evaluation
preview out_dir="results":
	@go run ./tools/preview -dir "{{out_dir}}" -open

# Generate the dashboard and terminal overview without opening a browser
preview-only out_dir="results":
	@go run ./tools/preview -dir "{{out_dir}}"

# Compile and open the LaTeX preview PDF (export first, then compile inside the results directory)
preview-pdf out_dir="results":
	@just export-latex {{out_dir}}/empirical_study.json
	@cd {{out_dir}} && nix shell nixpkgs#tectonic --command tectonic preview_paper.tex
	@open {{out_dir}}/preview_paper.pdf

# Local end-to-end evaluation pipeline on the 10-image set (the AWS run lives in the submission repo)
eval-all pack="cis" out_dir="results":
	@just eval-top10 {{pack}} {{out_dir}}
	@just eval-rq1 {{out_dir}}
	@just eval-rq3 fixtures/evaluation_dataset_top10_pinned.txt {{pack}} {{out_dir}}
	@just export-latex {{out_dir}}/empirical_study.json
	@just verify-integrity {{out_dir}}
	@printf '\nAll evaluation stages completed and verified.\n'

# Clean build artifacts and temporary files
clean:
	rm -rf bin/ results/ reports/ tests/reports/
	@echo "[SUCCESS] Clean completed"
