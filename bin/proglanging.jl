#!/usr/bin/env julia
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# proglanging — command line for the estate diagnostics console.
#
#   proglanging gate   <repo>              enforce policy on one repo (exit 1 on failure)
#   proglanging scan   [--local DIR] [--github ORG ...]  triage report (CSV + summary)
#   proglanging report <report.csv>        re-summarise an existing report
#   proglanging bench  [repo] [--reps N] [--csv OUT]  time the analyser on itself
#   proglanging help
#
# Exit codes: 0 ok · 1 gate failure · 2 usage error · 3 scan incomplete
# (a partial scan is never reported as success: exit 3 unless --allow-incomplete).

const ROOT = normpath(joinpath(dirname(@__FILE__), ".."))
pushfirst!(Base.LOAD_PATH, ROOT)

using ProglangingLanguages
import ProglangingLanguages: Classify, Languages, Policy, Report, Bench, Scan, Detect

const USAGE = """proglanging — estate language-policy analysis, evaluation and benchmarking

Usage:
  proglanging gate <repo> [--strict]
      Read <repo>/.language-policy.toml, walk it, detect anti-patterns, and
      decide. Exit 1 when the repo does not pass.

  proglanging scan [--local DIR ...] [--github ORG ...] [--csv OUT]
                   [--max-files N] [--shallow] [--allow-incomplete]
      Triage report in the estate schema (same columns as estate-scan.sh).
      --shallow uses GitHub language metadata instead of cloning each repo.

  proglanging report <report.csv>
      Re-count an existing estate-triage-report.csv by class and anti-pattern.

  proglanging bench [repo] [--reps N] [--csv OUT] [--baseline FILE]
      Time walk / detect / assess on `repo` (default: this package's own root).

  proglanging doctor
      Print runtime, version and policy-set sizes. Proof the tool runs.

Exit codes: 0 ok, 1 gate failed, 2 usage error, 3 scan incomplete."""

kw(args, flag; default = nothing) = begin
    i = findfirst(==(flag), args)
    (i === nothing || i == length(args)) && return default
    return args[i + 1]
end
hasflag(args, flag) = flag in args

function parse_multi(args, flag)
    out = String[]
    i = 1
    while i <= length(args)
        if args[i] == flag
            i += 1
            while i <= length(args) && !startswith(args[i], "--")
                push!(out, String(args[i]))
                i += 1
            end
            continue
        end
        i += 1
    end
    return out
end

function cmd_gate(args)
    repo = isempty(args) ? "." : String(args[1])
    isdir(repo) || (println(stderr, "not a directory: $repo"); return 2)
    pol = Policy.load(repo)
    if hasflag(args, "--strict")
        pol = Policy.with_strict(pol)
    end
    a = Classify.assess(repo; policy = pol)
    v = a.verdict
    println("repo:            ", v.name)
    println("role:            ", v.role, (v.declared_policy ? "" : " (no policy file — defaults)"))
    println("languages:       ", isempty(v.languages) ? "none detected" : join(v.languages, ", "))
    println("classification:  ", v.classification)
    println("errors:          ", isempty(v.errors) ? "none" : join(v.errors, ", "))
    println("warnings:        ", isempty(v.warnings) ? "none" : join(v.warnings, ", "))
    if !isempty(v.evidence)
        println("")
        println("evidence:")
        for (k, paths) in v.evidence
            println("  ", k)
            for p in paths
                println("    ", p)
            end
        end
    end
    if !isempty(a.notes)
        println("")
        println("notes:")
        for n in a.notes
            println("  ", n)
        end
    end
    println("")
    if v.passed
        println("✓ gate passed")
        return 0
    end
    println("✗ gate FAILED")
    for r in v.reasons
        println("  - ", r)
    end
    return 1
end

function cmd_scan(args)
    locals = parse_multi(args, "--local")
    orgs = parse_multi(args, "--github")
    csv = kw(args, "--csv"; default = "estate-triage-report.csv")
    max_files = parse(Int, something(kw(args, "--max-files"; default = "200000"), "200000"))
    deep = !hasflag(args, "--shallow")
    if isempty(locals) && isempty(orgs)
        println(stderr, "nothing to scan: pass --local DIR and/or --github ORG")
        return 2
    end
    rows = Classify.Verdict[]
    notes = String[]
    incomplete = false
    for dir in locals
        s = Scan.local_dir(dir; max_files = max_files)
        append!(rows, s.rows); append!(notes, s.notes); incomplete |= s.incomplete
    end
    for org in orgs
        s = Scan.github_org(org; deep = deep, max_files = max_files)
        append!(rows, s.rows); append!(notes, s.notes); incomplete |= s.incomplete
    end
    Report.write_csv(String(csv), rows)
    println(Report.summary_text(rows; title = "PROGLANGING SCAN COMPLETE", all_classes = !isempty(orgs)))
    if !isempty(notes)
        println("")
        println("scan notes:")
        for n in notes
            println("  - ", n)
        end
    end
    println("")
    println("report written: ", csv)
    if incomplete && !hasflag(args, "--allow-incomplete")
        println("✗ scan INCOMPLETE — do not treat this report as a clean result")
        return 3
    end
    return 0
end

function cmd_report(args)
    isempty(args) && (println(stderr, USAGE); return 2)
    path = String(args[1])
    isfile(path) || (println(stderr, "no such file: $path"); return 2)
    rows, header, notes = Report.read_csv(path)
    println("report: ", path)
    println("columns: ", join(header, ", "))
    println("rows:    ", length(rows))
    counts = Dict{String, Int}()
    pat = Dict{String, Int}()
    for r in rows
        k = haskey(r, :classification) ? String(r.classification) : "?"
        counts[k] = get(counts, k, 0) + 1
        if haskey(r, :antipatterns)
            for p in split(r.antipatterns, ',')
                p = strip(p)
                if isempty(p) || p == "NONE"
                    continue
                end
                pat[p] = get(pat, p, 0) + 1
            end
        end
    end
    println("")
    println("by classification")
    for (k, c) in sort!(collect(counts); by = kv -> (-kv[2], kv[1]))
        println("  ", rpad(k, 22), c)
    end
    println("")
    println("by anti-pattern")
    if isempty(pat)
        println("  (none recorded)")
    end
    for (k, c) in sort!(collect(pat); by = kv -> (-kv[2], kv[1]))
        println("  ", rpad(k, 26), c)
    end
    if !isempty(notes)
        println("")
        println("read notes:")
        for n in notes
            println("  - ", n)
        end
    end
    return 0
end

function cmd_bench(args)
    repo = isempty(args) ? ROOT : String(args[1])
    if !isdir(repo)
        println(stderr, "not a directory: $repo")
        return 2
    end
    reps = parse(Int, something(kw(args, "--reps"; default = "7"), "7"))
    out = kw(args, "--csv")
    baseline = kw(args, "--baseline")
    results = Bench.bench_analyser(repo; reps = reps)

    base = Dict{String, Float64}()
    if baseline !== nothing
        pth = String(baseline)
        if isfile(pth)
            for line in split(chomp(String(read(pth))), '\n')
                s = strip(line)
                (isempty(s) || startswith(s, "name,")) && continue
                f = Report.split_line(s)
                if length(f) >= 4
                    v = tryparse(Float64, f[4])
                    v === nothing || (base[f[1]] = v)
                end
            end
        else
            println(stderr, "baseline not found, ignoring: $pth")
        end
    end

    println("target: ", repo)
    println("runtime: ", ProglangingLanguages.runtime())
    regression = false
    for r in results
        println(Bench.summary_line(r))
        if haskey(base, r.name)
            cmp = Bench.compare_medians(base[r.name], r.median_ns)
            println("   vs baseline: ratio ", round(cmp.ratio; digits = 3), " → ", cmp.verdict)
            cmp.verdict === :slower && (regression = true)
        end
    end
    if out !== nothing
        open(String(out), "w") do io
            println(io, Bench.CSV_HEADER)
            for r in results
                println(io, Bench.to_csv_row(r))
            end
        end
        println("written: ", out)
    end
    if regression
        println("✗ benchmark regression beyond tolerance versus the baseline")
        return 1
    end
    return 0
end

function cmd_doctor(_)
    println("proglanging ", ProglangingLanguages.CONSOLE_VERSION)
    println(ProglangingLanguages.runtime())
    println("banned languages: ", length(Languages.BANNED), " · allowed: ", length(Languages.ALLOWED),
            " · warn-only: ", length(Languages.WARN_ONLY))
    println("detectors: 8 (NIF_WITHOUT_SNIF, UNVERIFIED_RUST, DENO_NOT_BUN, NODE_NOT_BUN, ",
            "DIRECT_FFI_NO_HEXADECA, IDRIS2_NOT_ABI_ROLE, NIX_PRESENT, VITE_DEBATE)")
    println("classes: ", join(Classify.CLASSES, ", "))
    return 0
end

function main()
    args = ARGS
    if isempty(args) || args[1] in ("help", "-h", "--help")
        println(USAGE)
        return isempty(args) ? 2 : 0
    end
    if args[1] == "--version"
        println(ProglangingLanguages.CONSOLE_VERSION)
        return 0
    end
    sub = args[1]
    rest = args[2:end]
    return if sub == "gate"
        cmd_gate(rest)
    elseif sub == "scan"
        cmd_scan(rest)
    elseif sub == "report"
        cmd_report(rest)
    elseif sub == "bench"
        cmd_bench(rest)
    elseif sub == "doctor"
        cmd_doctor(rest)
    else
        println(stderr, "unknown command: $sub")
        println(stderr, "")
        println(stderr, USAGE)
        2
    end
end

exit(main())
