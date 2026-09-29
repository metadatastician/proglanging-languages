# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Classify

The decision table, plus the gate verdict derived from it.

`classify` reproduces `classify_repo()` from `estate-scan.sh` exactly — same
inputs, same five outcomes, same order of precedence — so a report produced
here is comparable with the archived `estate-triage-report.csv` files. `gate`
is the *other* upstream behaviour (from `ci/language-gate.yml`), where errors
fail and warnings only fail under `strict`. Keeping them apart is the point:
a triage row and a CI verdict answer different questions, and conflating them
is how a gate ends up vacuous.
"""
module Classify

import ..Languages, ..Detect, ..Policy
using ..Languages: canonical, has_target
using ..Detect: Findings

export Verdict, classify, banned_present_excluding, gate, assess, describe, freshness

const CLASSES = (:DONE, :CLEAN, :MIGRATE, :KILL,
                 :COMMUNITY_OK, :COMMUNITY_NEEDS_FIX,
                 :ARCHIVED, :FORK, :SCAN_FAILED)

Base.@kwdef mutable struct Verdict
    "Either `github:<org>` or `local:<dir>`, as upstream reports it."
    source::String = "local"
    name::String = ""
    primary_language::String = "None"
    languages::Vector{String} = String[]
    classification::Symbol = :SCAN_FAILED
    "Union of errors and warnings, errors first — upstream `antipatterns` column."
    antipatterns::Vector{String} = String[]
    last_activity::String = "unknown"
    "Stars (GitHub rows) or commit count (local rows)."
    metric::Int = 0
    forks::Int = 0
    description::String = ""
    role::String = "unknown"
    declared_policy::Bool = false
    "Gate outcome fields, kept with the row so a report is self-explaining."
    passed::Bool = false
    errors::Vector{String} = String[]
    warnings::Vector{String} = String[]
    reasons::Vector{String} = String[]
    evidence::Dict{String, Vector{String}} = Dict{String, Vector{String}}()
    truncated::Bool = false
    unreadable::Int = 0
end

"""
    classify(langs, role, findings; exempt = String[]) -> Symbol

Faithful port of the upstream table:

| condition                                        | class                |
|--------------------------------------------------|----------------------|
| `role == "community-adapter"`                    | `COMMUNITY_OK` / `COMMUNITY_NEEDS_FIX` |
| no banned language, no findings                  | `DONE`               |
| no banned language, findings present             | `CLEAN`              |
| banned language present, target stack present    | `MIGRATE`            |
| banned language present, no target stack         | `KILL`               |
"""
function classify(langs::AbstractVector{<:AbstractString}, role::AbstractString,
                  findings::Findings; exempt::AbstractVector{<:AbstractString} = String[])
    banned = banned_present_excluding(langs, exempt)
    if lowercase(String(role)) == "community-adapter"
        return isempty(findings.errors) && isempty(findings.warnings) ? :COMMUNITY_OK : :COMMUNITY_NEEDS_FIX
    end
    any_finding = !isempty(findings.errors) || !isempty(findings.warnings)
    if isempty(banned)
        return any_finding ? :CLEAN : :DONE
    end
    return has_target(langs) ? :MIGRATE : :KILL
end

"""
    banned_present_excluding(langs, exempt; hard_only = false) -> Vector{String}

Banned languages present, minus those the policy exempts. Upstream's
`classify_repo` took a `role` parameter it never used; here both the role and
the severity policy bite.

`hard_only` downgrades `Languages.WARN_ONLY` entries to findings, which is how a
gate can be strict about Python in application code without failing on a
`flake.nix` that CI legitimately needs (docs/FINDINGS.adoc §F1).
"""
function banned_present_excluding(langs::AbstractVector{<:AbstractString},
                                 exempt::AbstractVector{<:AbstractString};
                                 hard_only::Bool = false)
    ex = Set(canonical.(String.(exempt)))
    if hard_only
        ex = union(ex, collect(Languages.WARN_ONLY))
    end
    out = String[]
    for lang in langs
        c = canonical(lang)
        if in(c, Languages.BANNED) && !in(c, ex) && !in(c, out)
            push!(out, c)
        end
    end
    return out
end

"""
    describe(root::AbstractString) -> String

First five lines of `README.md` / `README.adoc`, commas flattened, 120 chars —
the upstream `scan_local_dir` description rule, kept so reports diff cleanly.
"""
function describe(root::AbstractString)
    for name in ("README.md", "README.adoc", "README.rst", "README")
        path = joinpath(root, name)
        isfile(path) || continue
        text = try
            String(read(path))
        catch
            return ""
        end
        lines = String[]
        for line in split(text, '\n')
            s = strip(line)
            isempty(s) && continue
            startswith(s, "//") && continue
            push!(lines, s)
            length(lines) == 5 && break
        end
        out = replace(join(lines, ' '), ',' => ' ')
        out = replace(out, '\r' => ' ', '\n' => ' ')
        return String(first(out, min(ncodeunits(out), 120)))
    end
    return ""
end

"HEAD commit date and commit count, via `git`; `\"unknown\"`/`0` when absent."
function freshness(root::AbstractString)
    date = try
        s = String(read(`git -C $(root) log -1 --format=%ci`, String))
        strip(s)
    catch
        "unknown"
    end
    count = 0
    try
        raw = strip(String(read(`git -C $(root) rev-list --count HEAD`, String)))
        p = tryparse(Int, raw)
        if p !== nothing
            count = Int(p)
        end
    catch
        count = 0
    end
    return date, Int(count)
end

"""
    assess(root::AbstractString; policy = Policy.load(root), max_files = nothing) -> NamedTuple

Walk, detect and classify one repository directory.
"""
function assess(root::AbstractString; policy::Union{Policy.Policy, Nothing} = nothing,
                max_files::Union{Integer, Nothing} = nothing)
    pol = policy === nothing ? Policy.load(root) : policy
    cap = max_files === nothing ? pol.max_files : Int(max_files)
    files = Languages.walk(root; max_files = cap, exclude = pol.exclude)
    findings = Detect.analyse(root, files; nix_severity = pol.nix_severity, ffi_method = pol.ffi_method)
    cls = classify(files.langs, pol.role, findings; exempt = Policy.exemptions(pol))
    date, count = freshness(root)
    v = Verdict(
        source = "local:" * String(basename(abspath(root))),
        name = String(basename(abspath(root))),
        primary_language = isempty(files.langs) ? "None" : files.langs[1],
        languages = files.langs,
        classification = cls,
        antipatterns = Detect.names(findings),
        last_activity = date,
        metric = count,
        forks = 0,
        description = describe(root),
        role = pol.role,
        declared_policy = pol.declared,
        errors = findings.errors,
        warnings = findings.warnings,
        evidence = findings.evidence,
        truncated = files.truncated,
        unreadable = length(files.unreadable),
    )
    ok, reasons = gate(v, pol)
    v.passed = ok
    v.reasons = reasons
    return (verdict = v, passed = ok, reasons = reasons, files = files,
            findings = findings, policy = pol, notes = findings.notes)
end

"""
    gate(v::Verdict, policy) -> (passed::Bool, reasons::Vector{String})

The CI verdict. An error fails; a warning fails only under `strict`. A
truncated or partially unreadable scan fails too, because "no findings" from an
incomplete scan is not a pass — the estate's own `required_status_checks: []`
lesson, applied in the other direction.
"""
function gate(v::Verdict, policy::Policy.Policy = Policy.Policy())
    reasons = String[]
    hard = policy.nix_severity == "error"
    banned = banned_present_excluding(v.languages, Policy.exemptions(policy); hard_only = !hard)
    if !isempty(banned)
        push!(reasons, "banned languages detected: " * join(banned, ", "))
    end
    for e in v.errors
        detail = (e == "UNVERIFIED_RUST" && !isempty(policy.required_provers)) ?
                 " (required prover: " * join(policy.required_provers, ", ") * ")" : ""
        push!(reasons, "anti-pattern (error): " * e * detail)
    end
    if policy.strict
        for w in v.warnings
            push!(reasons, "anti-pattern (warning, strict mode): " * w)
        end
    end
    if v.classification === :SCAN_FAILED
        push!(reasons, "scan failed: this row is not evidence of anything")
    end
    v.truncated && push!(reasons, "scan truncated at max_files: absence of findings is not proof of absence")
    v.unreadable > 0 && push!(reasons, "unreadable directories: $(v.unreadable) (scan incomplete)")
    policy.declared || push!(reasons, "no .language-policy.toml — defaults applied (declare a policy to make this meaningful)")
    return isempty(reasons), reasons
end

end # module
