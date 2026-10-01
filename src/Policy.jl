# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Policy

`.language-policy.toml` reader — the per-repo declaration the estate's language
gate is supposed to consume.

Upstream parses this file with `python3 -c "import toml"` inside the workflow,
after `pip install toml --break-system-packages ... || true`; when the install
fails the step dies for an unrelated reason and, worse, the gate's own
`|| true` swallows it. Here it is TOML from the Julia standard library, and a
missing or unparseable policy is reported instead of assumed (see
`docs/FINDINGS.adoc` §F5).
"""
module Policy

import TOML

const ROLES = ("core", "community-adapter", "tool", "research", "deprecated")

Base.@kwdef struct Config
    role::String = "core"
    extra_allowed::Vector{String} = String[]
    required_provers::Vector{String} = ["gnatprove"]
    js_runtime::String = "bun"
    ffi_method::String = "hexadeca"
    "Severity for `NIX_PRESENT`: \"warn\" (default) or \"error\"."
    nix_severity::String = "warn"
    "Warnings also fail the gate."
    strict::Bool = false
    "Cap on files examined per repo; truncation is reported, never hidden."
    max_files::Int = 200_000
    "Repo-relative paths the gate does not inspect (fixtures, vendored mirrors)."
    exclude::Vector{String} = String[]
    "False when no policy file exists and defaults were applied."
    declared::Bool = false
    notes::Vector{String} = String[]
end

function strings(v)
    v isa AbstractVector || return String[]
    return String[String(x) for x in v if x isa AbstractString]
end

function parse_int(x, default::Int)
    if x isa Integer
        return Int(x)
    elseif x isa AbstractString
        t = tryparse(Int, String(x))
        return t === nothing ? default : t
    end
    return default
end

function parse_bool(x, default::Bool)
    if x isa Bool
        return x
    elseif x isa AbstractString
        return lowercase(String(x)) in ("1", "true", "yes", "on")
    end
    return default
end

"""
    load(root::AbstractString; path = nothing) -> Config

Read `<root>/.language-policy.toml`, or return the strict default with a note
when it is absent. Never throws: an unreadable or malformed policy becomes a
note plus defaults, so a broken policy file cannot silently mean "no policy".
"""
function load(root::AbstractString; path::Union{AbstractString, Nothing} = nothing)
    file = path === nothing ? joinpath(root, ".language-policy.toml") : String(path)
    if !isfile(file)
        return Config(declared = false,
                      notes = String["no .language-policy.toml at repo root — strict default policy applied"])
    end
    local raw
    try
        raw = TOML.parse(String(read(file)))
    catch e
        return Config(declared = true,
                      notes = String["policy file present but unparseable: " * sprint(showerror, e)])
    end

    function g(sec, key, default)
        if haskey(raw, sec) && raw[sec] isa Dict && haskey(raw[sec], key)
            return raw[sec][key]
        end
        return default
    end

    role_s = String(g("policy", "role", "core"))
    notes = String[]
    if !(role_s in ROLES)
        known = join(ROLES, ", ")
        push!(notes, "unknown role $role_s — treated as core (known: $known)")
        role_s = "core"
    end

    extra = strings(g("allowed_languages", "extra_allowed", String[]))
    provers = strings(g("provers", "required", ["gnatprove"]))
    nix_s = lowercase(String(g("gate", "nix_severity", "warn")))
    if nix_s != "warn" && nix_s != "error"
        push!(notes, "unknown gate.nix_severity $nix_s — using warn")
        nix_s = "warn"
    end

    return Config(
        role = role_s,
        extra_allowed = extra,
        required_provers = isempty(provers) ? String[] : provers,
        js_runtime = String(g("runtime", "js", "bun")),
        ffi_method = String(g("ffi", "method", "hexadeca")),
        nix_severity = nix_s,
        strict = parse_bool(g("gate", "strict", false), false),
        max_files = parse_int(g("gate", "max_files", 200_000), 200_000),
        exclude = strings(g("gate", "exclude", String[])),
        declared = true,
        notes = notes,
    )
end

"""
    with_strict(pol::Config) -> Config

Return `pol` with `strict` forced on. Spelled out field by field because
`Base.@kwdef` gives no copy-and-override constructor, and a struct literal that
silently dropped a field would be worse than the verbosity.
"""
function with_strict(pol::Config)
    return Config(role = pol.role, extra_allowed = pol.extra_allowed,
                  required_provers = pol.required_provers, js_runtime = pol.js_runtime,
                  ffi_method = pol.ffi_method, nix_severity = pol.nix_severity,
                  strict = true, max_files = pol.max_files, exclude = pol.exclude,
                  declared = pol.declared,
                  notes = vcat(pol.notes, String["--strict: warnings fail too"]))
end

"""Languages exempted from the ban by this policy (adapters only, upstream rule)."""
function exemptions(p::Config)
    return p.role == "community-adapter" ? p.extra_allowed : String[]
end

end # module
