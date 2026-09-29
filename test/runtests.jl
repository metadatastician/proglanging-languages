# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
module ProglangingLanguagesTests

using Test
using ProglangingLanguages

import ProglangingLanguages: Languages, Policy, Detect, Classify, Report, Bench, Scan

const FIX = joinpath(@__DIR__, "fixtures")
const REPO_ROOT = normpath(joinpath(@__DIR__, ".."))

assess(name::AbstractString; kwargs...) = Classify.assess(joinpath(FIX, name); kwargs...)

@testset "language map and policy sets" begin
    @test Languages.language_for_path("src/Analysis.jl") == "Julia"
    @test Languages.language_for_path("analysis.R") == "R"
    @test Languages.language_for_path("notes.md") == "Markdown"
    @test Languages.language_for_path("docs/intro.adoc") == "AsciiDoc"
    @test Languages.language_for_path("Containerfile") == "Dockerfile"
    @test Languages.language_for_path("Makefile") == "Makefile"
    @test Languages.language_for_path("justfile") == "Just"
    @test Languages.language_for_path("main.unknownext") === nothing
    @test Languages.canonical("CSharp") == "C#"
    @test Languages.canonical("VisualBasic") == "Visual Basic"
    @test "Python" in Languages.BANNED
    @test "Julia" in Languages.ALLOWED
    # A ban that lists Nix and allows Nix cannot both win; §F1 records the ruling.
    @test "Nix" in Languages.WARN_ONLY
end

@testset "classification decision table" begin
    none = Detect.Findings()
    @test Classify.classify(["Julia"], "core", none) === :DONE
    @test Classify.classify(["Shell", "Markdown"], "core", none) === :DONE
    @test Classify.classify(["Python"], "core", none) === :KILL
    @test Classify.classify(["Python", "Julia"], "core", none) === :MIGRATE
    @test Classify.classify(["Julia"], "core", Detect.Findings(warnings = ["NIX_PRESENT"])) === :CLEAN
    @test Classify.classify(["Julia"], "core", Detect.Findings(errors = ["DENO_NOT_BUN"])) === :CLEAN
    @test Classify.classify(["ReScript"], "community-adapter", none) === :COMMUNITY_OK
    @test Classify.classify(["ReScript"], "community-adapter", Detect.Findings(errors = ["X"])) ===
          :COMMUNITY_NEEDS_FIX
    @test :KILL in Classify.CLASSES
end

@testset "gate verdict differs from triage class, on purpose" begin
    nix_only = Classify.Verdict(languages = ["Nix", "Julia"], classification = :MIGRATE,
                                warnings = ["NIX_PRESENT"], declared_policy = true)
    ok_loose, why_loose = Classify.gate(nix_only, Policy.Policy(nix_severity = "warn", declared = true))
    @test ok_loose
    @test isempty(why_loose)

    ok_strict, why_strict = Classify.gate(nix_only, Policy.Policy(nix_severity = "error", declared = true))
    @test !ok_strict
    @test occursin("Nix", join(why_strict, " "))

    warn_only = Classify.Verdict(languages = ["Julia"], classification = :CLEAN,
                                 warnings = ["VITE_DEBATE"], declared_policy = true)
    @test Classify.gate(warn_only, Policy.Policy(declared = true))[1]
    @test !Classify.gate(warn_only, Policy.Policy(strict = true, declared = true))[1]

    trunc = Classify.Verdict(languages = ["Julia"], classification = :DONE,
                             truncated = true, declared_policy = true)
    ok_trunc, why_trunc = Classify.gate(trunc, Policy.Policy(declared = true))
    @test !ok_trunc
    @test occursin("truncated", join(why_trunc, " "))

    failed_scan = Classify.Verdict(languages = ["Julia"], classification = :SCAN_FAILED,
                                   declared_policy = true)
    @test !Classify.gate(failed_scan, Policy.Policy(declared = true))[1]

    undeclared = Classify.Verdict(languages = ["Julia"], classification = :DONE, declared_policy = false)
    ok_und, why_und = Classify.gate(undeclared, Policy.Policy(declared = false))
    @test !ok_und
    @test occursin("no .language-policy.toml", join(why_und, " "))
end

@testset "fixture repositories classify as designed" begin
    @test assess("clean_repo").verdict.classification === :DONE
    @test assess("clean_repo").passed

    k = assess("kill_repo")
    @test k.verdict.classification === :KILL
    @test !k.passed
    @test occursin("Python", join(k.verdict.languages, " "))

    @test assess("migrate_repo").verdict.classification === :MIGRATE
    @test assess("deno_repo").verdict.classification === :CLEAN
    @test "DENO_NOT_BUN" in assess("deno_repo").verdict.errors

    ru = assess("rust_unverified")
    @test "UNVERIFIED_RUST" in ru.verdict.errors
    @test "DIRECT_FFI_NO_HEXADECA" in ru.verdict.errors
    @test !ru.passed

    rv = assess("rust_verified")
    @test rv.verdict.classification === :DONE
    @test isempty(rv.verdict.errors)

    nx = assess("nix_repo")
    @test "NIX_PRESENT" in nx.verdict.warnings
    @test !("NIX_PRESENT" in nx.verdict.errors)
    @test nx.verdict.classification === :MIGRATE

    vt = assess("vite_repo")
    @test "VITE_DEBATE" in vt.verdict.warnings
    @test vt.verdict.classification === :MIGRATE

    @test assess("adapter_repo").verdict.classification === :COMMUNITY_OK
    @test "IDRIS2_NOT_ABI_ROLE" in assess("idr_repo").verdict.errors
end

@testset "evidence points at a file, not just at a pattern name" begin
    a = assess("rust_unverified")
    @test haskey(a.verdict.evidence, "UNVERIFIED_RUST")
    paths = a.verdict.evidence["UNVERIFIED_RUST"]
    @test any(p -> endswith(p, "Cargo.toml"), abspath.(paths))
end

@testset "truncation is reported, never hidden" begin
    t = assess("truncated_repo"; max_files = 3)
    @test t.files.truncated
    @test t.files.considered == 3
    @test occursin("truncated", join(t.reasons, " "))
    @test !t.passed
end

@testset "vendored trees are not evidence" begin
    n = assess("nested_repo")
    @test n.verdict.languages == ["Julia"]
    @test n.verdict.classification === :DONE
end

@testset "policy file handling" begin
    p = Policy.load(joinpath(FIX, "clean_repo"))
    @test p.declared
    @test p.role == "core"
    @test isempty(p.required_provers)

    d = Policy.load(joinpath(FIX, "kill_repo"))
    @test !d.declared
    @test d.role == "core"
    @test !isempty(d.notes)

    mkdir(joinpath(FIX, "broken_policy_repo"))
    try
        write(joinpath(FIX, "broken_policy_repo", ".language-policy.toml"), "this is not = valid toml [[")
        b = Policy.load(joinpath(FIX, "broken_policy_repo"))
        @test b.declared
        @test any(n -> occursin("unparseable", n), b.notes)
    finally
        rm(joinpath(FIX, "broken_policy_repo"); recursive = true, force = true)
    end

    u = Policy.Policy(role = "nonsense")
    @test u.strict == false
    s = Policy.with_strict(Policy.Policy(nix_severity = "warn", max_files = 42))
    @test s.strict && s.nix_severity == "warn" && s.max_files == 42
end

@testset "report round-trips the estate CSV schema" begin
    rows = [assess("clean_repo").verdict, assess("kill_repo").verdict, assess("nix_repo").verdict]
    csv = Report.to_csv(rows)
    lines = split(chomp(csv), '\n')
    @test lines[1] == Report.HEADER
    @test length(lines) == 1 + length(rows)
    @test !occursin('\n', lines[2])

    path = joinpath(mktempdir(), "estate-triage-report.csv")
    Report.write_csv(path, rows)
    loaded, header, notes = Report.read_csv(path)
    @test length(loaded) == 3
    @test isempty(notes)
    @test header[1] == "source"
    @test loaded[1].classification == "DONE"
    @test loaded[2].classification == "KILL"
    @test loaded[3].classification == "MIGRATE"
    @test startswith(loaded[1].name, "clean_repo")

    @test Report.csv_field("plain") == "plain"
    @test Report.csv_field("with, comma") == "\"with, comma\""
    @test Report.csv_field("say \"hi\"") == "\"say \"\"hi\"\"\""
    @test Report.split_line(Report.csv_field("a,b")) == ["a,b"]

    c = Report.by_class(rows)
    @test c["DONE"] == 1 && c["KILL"] == 1 && c["MIGRATE"] == 1
    all_c = Report.by_class(rows; all_classes = true)
    @test all_c["ARCHIVED"] == 0
    @test !occursin("no rows", Report.summary_text(rows))
    @test occursin("nothing was measured", Report.summary_text(Classify.Verdict[]; all_classes = true))
    @test occursin("| repo |", Report.to_markdown(rows))
end

@testset "a short CSV row is padded and announced, never dropped" begin
    path = joinpath(mktempdir(), "partial.csv")
    write(path, Report.HEADER * "\nlocal:base,short,,,\n")
    loaded, _, notes = Report.read_csv(path)
    @test length(loaded) == 1
    @test any(n -> occursin("padded", n), notes)
end

@testset "benchmarks: median and MAD on data with an outlier" begin
    v = [10.0, 11.0, 9.0, 10.5, 10.2, 9.8, 500.0]
    @test Bench.median(v) == 10.2
    @test Bench.median([1.0, 2.0]) == 1.5
    @test !isfinite(Bench.median(Float64[]))
    @test Bench.mad([1.0, 1.0, 1.0]) == 0.0
    @test Bench.mad(v) >= 0.0
    @test Bench.compare_medians(100.0, 150.0).verdict === :slower
    @test Bench.compare_medians(100.0, 50.0).verdict === :faster
    @test Bench.compare_medians(100.0, 105.0).verdict === :within_tolerance
    @test isnan(Bench.compare_medians(0.0, 1.0).ratio)
    @test length(split(Bench.to_csv_row(Bench.Result("x", 1, 0, [1.0], 1.0, 1.0, 1.0, 1.0, 0.0,
                                                     "1.10.0", 64, 1)), ",")) == length(split(Bench.CSV_HEADER, ","))
    @test occursin("\"name\": \"x\"", Bench.to_json(Bench.Result("x", 1, 0, [1.0], 1.0, 1.0, 1.0, 1.0,
                                                                  0.0, "1.10.0", 64, 1)))
end

@testset "the analyser times itself" begin
    res = Bench.bench_analyser(joinpath(FIX, "clean_repo"); reps = 3)
    @test length(res) == 3
    @test map(r -> r.name, res) == ["walk", "detect", "assess"]
    @test all(r -> r.reps == 3 && r.warmup == 3, res)
    @test all(r -> isfinite(r.median_ns) && r.median_ns > 0, res)
    @test all(r -> r.min_ns <= r.median_ns <= r.max_ns, res)
    @test occursin("ms", Bench.summary_line(res[1]))
end

@testset "github rows are built from gh output without touching the network" begin
    s = Scan.Scan(rows = Classify.Verdict[Classify.Verdict(name = "x", classification = :SCAN_FAILED)],
                  incomplete = true, notes = String["gh failed"])
    @test length(s) == 1
    @test s.incomplete
    @test !isempty(s.notes)
    git_only = Scan.local_dir(FIX)
    @test git_only.incomplete && isempty(git_only.rows)

    missing_dir = Scan.local_dir(joinpath(FIX, "no_such_directory"))
    @test missing_dir.incomplete
    @test isempty(missing_dir.rows)
    empty_dir = mktempdir()
    nodata = Scan.local_dir(empty_dir)
    @test nodata.incomplete
    @test any(n -> occursin("covers 0 repos", n), nodata.notes)
end

@testset "scan over a directory of repos" begin
    s = Scan.local_dir(FIX; max_files = 200_000, require_git = false)
    @test length(s) >= 12
    @test any(r -> r.name == "clean_repo", s.rows)
    @test any(r -> r.classification === :KILL, s.rows)
    @test any(r -> r.truncated, s.rows) === false
    byclass = Report.by_class(s.rows)
    @test haskey(byclass, "DONE")
end

@testset "the console passes its own gate" begin
    a = Classify.assess(REPO_ROOT)
    if !a.verdict.passed
        @warn "self-gate reasons" a.verdict.reasons
    end
    @test a.verdict.passed
    @test a.verdict.role == "tool"
    @test !("DIRECT_FFI_NO_HEXADECA" in a.verdict.errors)
    @test !a.verdict.truncated
    # Fixtures are excluded by declaration — and only from this repo's own walk.
    @test !any(p -> endswith(p, ".py"), a.files.paths)
    @test !any(p -> occursin("fixtures", p), a.files.paths)
    @test any(p -> endswith(p, ".py"), assess("kill_repo").files.paths)
end

@testset "public API surface" begin
    @test ProglangingLanguages.CONSOLE_VERSION isa String
    @test occursin("julia", ProglangingLanguages.runtime())
    r = ProglangingLanguages.analyze_directory(joinpath(FIX, "kill_repo"))
    @test r.verdict.classification === :KILL
    sweep = ProglangingLanguages.analyze(joinpath(FIX, "clean_repo"))
    @test sweep isa ProglangingLanguages.Sweep
    @test length(sweep.rows) == 1
    @test occursin("PROGLANGING SCAN COMPLETE", ProglangingLanguages.summary(sweep.rows))
end

end # module
