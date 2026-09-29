# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    ProglangingLanguages

Diagnostics and monitoring console for a polyglot development estate: which
languages a repository actually contains, which of them the estate's language
policy forbids, which architectural anti-patterns it shows, and how long the
analysis itself takes.

Standard library only (`TOML` is a stdlib). No network access at analysis time:
`Scan.github_org` shells out to `gh` when you ask for live org data, and every
other path is filesystem-only, so a report is reproducible from a checkout.

```julia
using ProglangingLanguages
rep = analyze("/path/to/estate-repos")          # local directories
println(summary(rep.rows))                      # triage table
rep.incomplete && error("partial scan — not a pass")

v = analyze_directory("/path/to/one-repo")
v.verdict.classification                          # :DONE / :CLEAN / :MIGRATE / :KILL / ...
v.passed, v.reasons                                # the gate verdict and why
```

Submodules: `Languages` (detection + policy sets), `Policy`
(`.language-policy.toml`), `Detect` (anti-patterns), `Classify` (decision table
and gate), `Report` (CSV/Markdown/summary), `Scan` (local + GitHub),
`Bench` (timing harness).
"""
module ProglangingLanguages

include("Languages.jl")
include("Policy.jl")
include("Detect.jl")
include("Classify.jl")
include("Report.jl")
include("Bench.jl")
include("Scan.jl")

using .Languages
using .Policy
using .Detect
using .Classify
using .Report
using .Bench
using .Scan

export Languages, Policy, Detect, Classify, Report, Bench, Scan

"""Everything a caller needs to decide; `incomplete` can never be confused with `passed`."""
Base.@kwdef mutable struct Sweep
    rows::Vector{Classify.Verdict} = Classify.Verdict[]
    incomplete::Bool = false
    notes::Vector{String} = String[]
end

const CONSOLE_VERSION = "0.1.0"

"Julia `VERSION` this build ran under — recorded with every artefact."
runtime() = "julia $(VERSION) ($(Sys.WORD_SIZE)-bit, $(Threads.nthreads()) threads, $(Sys.MACHINE))"

"""
    analyze_directory(root::AbstractString; max_files = nothing, policy = nothing) -> NamedTuple

One repository: inventory, findings, classification, and the gate verdict.
"""
function analyze_directory(root::AbstractString; kwargs...)
    return Classify.assess(root; kwargs...)
end

"""
    analyze(base::AbstractString; github = String[], max_files = 200_000, deep = true) -> Sweep

Local checkouts under `base` (a directory of repos, as `--local` meant it
upstream) plus any GitHub orgs named in `github`. `incomplete` is true when any
part of the sweep failed or was truncated: the estate's rule that a census which
cannot fail is not a measurement, applied to this console.
"""
function analyze(base::AbstractString; github::AbstractVector{<:AbstractString} = String[],
                 max_files::Integer = 200_000, deep::Bool = true)
    rows = Classify.Verdict[]
    notes = String[]
    incomplete = false
    if !isempty(base)
        s = Scan.local_dir(base; max_files = max_files)
        append!(rows, s.rows)
        append!(notes, s.notes)
        incomplete = incomplete || s.incomplete
    end
    for org in github
        s = Scan.github_org(String(org); deep = deep, max_files = max_files)
        append!(rows, s.rows)
        append!(notes, s.notes)
        incomplete = incomplete || s.incomplete
    end
    return Sweep(rows = rows, incomplete = incomplete, notes = notes)
end

"Summary text for the console / CI log."
summary(rows::AbstractVector{Classify.Verdict}; kwargs...) = Report.summary_text(rows; kwargs...)

end # module
