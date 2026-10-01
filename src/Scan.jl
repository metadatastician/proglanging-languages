# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Scan

Repo discovery: local checkouts and GitHub organisations.

Ported from `scan_local_dir()` and `scan_github_org()` in `estate-scan.sh`. The
upstream property that earns its keep is the loud partial-scan failure — a
`gh` 502 under `set -e` used to abort everything, and an aborted org used to be
publishable as "no Deno estate-wide". Both are reproduced here as `incomplete`,
which the gate treats as a failure rather than as a clean sheet.

`require_git = false` accepts plain directories as repos, for estates that are
mirrors, vendor drops, or test fixtures rather than working clones.

`deep = true` clones each repo to scan file contents (upstream's behaviour);
`deep = false` scans GitHub's own language metadata only and says so. Shallow
rows are never reported as "no anti-patterns".
"""
module Scan

import ..Languages, ..Detect, ..Classify, ..Policy

Base.@kwdef struct Result
    rows::Vector{Classify.Verdict} = Classify.Verdict[]
    incomplete::Bool = false
    notes::Vector{String} = String[]
end

Base.length(s::Result) = length(s.rows)

function flatten_notes(rows, notes, src, name, extra)
    for e in extra
        push!(notes, "$src/$name: $e")
    end
    return nothing
end

"""
    local_dir(base::AbstractString; max_files = 200_000) -> Result

Every immediate subdirectory of `base` that contains a `.git` directory.
"""
function local_dir(base::AbstractString; max_files::Integer = 200_000, require_git::Bool = true)
    rows = Classify.Verdict[]
    notes = String[]
    incomplete = false
    if !isdir(base)
        return Result(rows, true, String["directory not found: $base"])
    end
    found = 0
    for name in sort!(collect(readdir(base)))
        path = joinpath(base, name)
        if require_git
            isdir(joinpath(path, ".git")) || continue
        else
            isdir(path) || continue
            isempty(readdir(path)) && continue
        end
        found += 1
        a = try
            Classify.assess(path; max_files = max_files)
        catch e
            push!(notes, "local/$name: assessment raised $(sprint(showerror, e))")
            incomplete = true
            nothing
        end
        a === nothing && continue
        push!(rows, a.verdict)
        flatten_notes(rows, notes, "local", name, a.notes)
        a.files.truncated && (incomplete = true)
    end
    if found == 0
        incomplete = true
        push!(notes, "no git repositories found directly under $base — this scan covers 0 repos")
    end
    return Result(rows, incomplete, notes)
end

json_get(d, k, default) = (haskey(d, k) && d[k] !== nothing) ? d[k] : default

langs_of(item) = begin
    out = String[]
    for node in json_get(item, "languages", Any[])
        n = node isa Dict ? get(node, "node", nothing) : nothing
        nm = n isa Dict ? get(n, "name", nothing) : nothing
        if nm !== nothing
            c = Languages.canonical(String(nm))
            in(c, out) || push!(out, c)
        end
    end
    out
end

"""
    github_org(org::AbstractString; gh = "gh", limit = 2000, attempts = 3,
               deep = true, depth = 1, max_files = 200_000) -> Result

List an org with the `gh` CLI and, when `deep`, shallow-clone each repo to run
the detectors over its default branch.
"""
function github_org(org::AbstractString; gh::AbstractString = "gh", limit::Integer = 2000,
                    attempts::Integer = 3, deep::Bool = true, depth::Integer = 1,
                    max_files::Integer = 200_000, tmp::AbstractString = mktempdir())
    rows = Classify.Verdict[]
    notes = String[]
    incomplete = false

    cmd = `$gh repo list $org --limit $(Int(limit)) --json name,primaryLanguage,languages,isArchived,isFork,pushedAt,stargazerCount,forkCount,description`
    parsed::Union{Nothing, Vector{Any}} = nothing
    lasterr = ""
    for attempt in 1:Int(attempts)
        try
            out = String(read(pipeline(cmd; stderr = devnull)))
            parsed = collect(Base.JSON.parse(out))
            break
        catch e
            lasterr = sprint(showerror, e)
            parsed = nothing
            attempt < attempts && sleep(2.0 * attempt)
        end
    end
    if parsed === nothing
        push!(notes, "gh repo list $org failed after $attempts attempts ($lasterr) — org $org is NOT covered by this report")
        return Result(rows, true, notes)
    end

    for item in parsed
        item isa Dict || continue
        name = string(json_get(item, "name", "?"))
        primary_item = json_get(item, "primaryLanguage", nothing)
        primary = primary_item isa Dict ? Languages.canonical(string(get(primary_item, "name", "None"))) : "None"
        langs = langs_of(item)
        isempty(langs) && primary != "None" && push!(langs, primary)
        archived = istrue(json_get(item, "isArchived", false))
        isfork = istrue(json_get(item, "isFork", false))
        pushed = string(json_get(item, "pushedAt", "unknown"))
        stars = something(tryparse(Int, string(json_get(item, "stargazerCount", 0))), 0)
        forks = something(tryparse(Int, string(json_get(item, "forkCount", 0))), 0)
        desc = string(json_get(item, "description", ""))

        v = Classify.Verdict(source = "github:$org", name = name, primary_language = primary,
                             languages = langs, last_activity = pushed, metric = stars,
                             forks = forks, description = desc)

        if archived
            v.classification = :ARCHIVED
            push!(rows, v); continue
        elseif isfork
            v.classification = :FORK
            push!(rows, v); continue
        end

        if !deep
            findings = Detect.Findings(notes = String["shallow scan: GitHub language metadata only, no file-content detectors"])
            v.classification = Classify.classify(langs, "unknown", findings)
            v.reasons = String["shallow: anti-pattern detectors not run — CLEAN here means only that no banned language is reported by GitHub"]
            push!(rows, v); continue
        end

        dest = joinpath(tmp, name)
        clone = `$gh repo clone $org/$name $dest -- --depth $(Int(depth)) --quiet`
        ok = try
            success(pipeline(clone; stdout = devnull, stderr = devnull))
        catch e
            push!(notes, "github/$org/$name: clone raised $(sprint(showerror, e))")
            false
        end
        if !ok || !isdir(dest)
            v.classification = :SCAN_FAILED
            v.antipatterns = String["CLONE_ERROR"]
            incomplete = true
            push!(rows, v)
            continue
        end

        pol = Policy.load(dest)
        files = Languages.walk(dest; max_files = max_files, exclude = pol.exclude)
        findings = Detect.analyse(dest, files; nix_severity = pol.nix_severity, ffi_method = pol.ffi_method)
        v.classification = Classify.classify(files.langs, pol.role, findings; exempt = Policy.exemptions(pol))
        v.languages = files.langs
        v.primary_language = isempty(files.langs) ? primary : files.langs[1]
        v.antipatterns = Detect.names(findings)
        v.errors = findings.errors
        v.warnings = findings.warnings
        v.evidence = findings.evidence
        v.truncated = files.truncated
        v.unreadable = length(files.unreadable)
        v.role = pol.role
        v.declared_policy = pol.declared
        files.truncated && (incomplete = true)
        flatten_notes(rows, notes, "github/$org", name, findings.notes)
        rm(dest; recursive = true, force = true)
        push!(rows, v)
    end

    if isempty(rows)
        incomplete = true
        push!(notes, "org $org produced 0 rows — an empty org is not the same as a clean estate")
    end
    return Result(rows, incomplete, notes)
end

istrue(x) = x === true || (x isa AbstractString && lowercase(x) in ("true", "1", "yes"))

end # module
