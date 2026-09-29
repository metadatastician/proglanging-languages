# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Detect

Architectural anti-pattern detectors.

These are a direct port of the eight detectors that exist in two divergent
copies upstream — `detect_antipatterns()` in `estate-scan.sh` and the inline
`Check anti-patterns` step of `ci/language-gate.yml`. The upstream copies
disagree on severity (the scan treats every hit alike and derives
classification from it; the gate splits them into errors and warnings) and on
pattern sets. Both behaviours are kept here and separated on purpose:
`Classify.classify` consumes the union, `Classify.gate` consumes the split.

Unlike upstream, detection runs over the walked file list only, so `.git`,
`node_modules`, `target`, `_build` and `vendor` contents can never produce a
finding — and never mask one either (see `docs/FINDINGS.adoc` §F4).
"""
module Detect

using ..Languages: Files

export Findings, Finding, analyse, names

"""Files larger than this are not content-scanned (counted, then skipped)."""
const TEXT_SIZE_LIMIT = 512 * 1024

struct Finding
    name::String
    severity::Symbol   # :error or :warn
    paths::Vector{String}
end

Base.@kwdef struct Findings
    errors::Vector{String} = String[]
    warnings::Vector{String} = String[]
    notes::Vector{String} = String[]
    "Pattern name → offending paths (first few, for actionable output)."
    evidence::Dict{String, Vector{String}} = Dict{String, Vector{String}}()
end

Base.isempty(f::Findings) = isempty(f.errors) && isempty(f.warnings)

"""All pattern names found, errors first — the upstream `antipatterns` field."""
function names(f::Findings)
    out = String[]
    for n in f.errors
        in(n, out) || push!(out, n)
    end
    for n in f.warnings
        in(n, out) || push!(out, n)
    end
    return out
end

function index(root::AbstractString, files::Files)
    by_base = Dict{String, Vector{String}}()
    by_ext = Dict{String, Vector{String}}()
    for rel in files.paths
        full = joinpath(root, rel)
        b = lowercase(String(basename(rel)))
        push!(get!(by_base, b, String[]), full)
        ext = String(splitext(rel)[2])
        if !isempty(ext)
            ext = lowercase(startswith(ext, ".") ? ext[2:end] : ext)
            push!(get!(by_ext, ext, String[]), full)
        end
    end
    return by_base, by_ext
end

function readtext(path::AbstractString)
    try
        isfile(path) || return nothing
        filesize(path) > TEXT_SIZE_LIMIT && return nothing
        return String(read(path))
    catch
        return nothing
    end
end

"""Absolute paths for any of `exts`, from a pre-built extension index."""
function paths_for(by_ext, exts)
    return vcat([get(by_ext, e, String[]) for e in exts]...)
end

"""
    analyse(root, files; nix_severity = "warn") -> Findings

Run all eight detectors over an already-walked repository.
"""
function analyse(root::AbstractString, files::Files; nix_severity::AbstractString = "warn",
                 ffi_method::AbstractString = "hexadeca")
    by_base, by_ext = index(root, files)
    errs = String[]
    warns = String[]
    notes = String[]
    ev = Dict{String, Vector{String}}()

    function record!(name::AbstractString, paths::Vector{String}, severity::Symbol)
        isempty(paths) && return
        list = name == "NIX_PRESENT" ? (nix_severity == "error" ? errs : warns) :
               name == "VITE_DEBATE" ? warns :
               severity === :error ? errs : warns
        push!(list, String(name))
        ev[String(name)] = first(paths, 5)
        return nothing
    end

    # ── 1. NIF without SNIF ────────────────────────────────────────────────
    nif_pat = r"erl_nif\.h|:nif\b|\bNIF\b|#\[rustler::nif\]"
    nif_src = paths_for(by_ext, ["rs", "erl", "ex", "c", "h"])
    nif_hits = String[p for p in nif_src if (t = readtext(p)) !== nothing && occursin(nif_pat, t)]
    if !isempty(nif_hits)
        snif_src = vcat(nif_src, paths_for(by_ext, ["ex", "erl", "rs", "toml", "md", "adoc"]))
        has_snif = any(snif_src) do p
            t = readtext(p)
            t !== nothing && occursin(r"snif|SNIF|safe_nif", t)
        end
        has_snif || record!("NIF_WITHOUT_SNIF", nif_hits, :error)
    end

    # ── 2. Unverified Rust ─────────────────────────────────────────────────
    cargo = get(by_base, "cargo.toml", String[])
    filter!(p -> !occursin(r"(^|/)target/", p), cargo)
    if !isempty(cargo)
        prover_pat = r"#\[requires\]|#\[ensures\]|#\[invariant\]|#\[proof\]|kani::proof|creusot|prusti|verus!|gnatprove"
        rs = get(by_ext, "rs", String[])
        has_prover = any(rs) do p
            t = readtext(p)
            t !== nothing && occursin(prover_pat, t)
        end
        for cfg in ("kani-args.toml", ".gnatprove", "creusot.toml", "prusti.toml")
            haskey(by_base, lowercase(cfg)) && (has_prover = true)
        end
        if !has_prover
            has_prover = any(cargo) do p
                t = readtext(p)
                t !== nothing && occursin(r"kani|creusot|prusti|verus|gnatprove", t)
            end
        end
        has_prover || record!("UNVERIFIED_RUST", first(cargo, 5), :error)
    end

    # ── 3. Deno (should be Bun) ────────────────────────────────────────────
    deno = vcat([get(by_base, b, String[]) for b in ("deno.json", "deno.jsonc", "deno.lock")]...)
    record!("DENO_NOT_BUN", deno, :error)

    # ── 4. Node/Yarn/pnpm without Bun ─────────────────────────────────────
    node = vcat([get(by_base, b, String[]) for b in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")]...)
    bun = vcat([get(by_base, b, String[]) for b in ("bun.lockb", "bun.lock", "bunfig.toml")]...)
    isempty(node) || isempty(bun) || record!("NODE_NOT_BUN", node, :error)

    # ── 5. Direct C FFI without hexadeca ───────────────────────────────────
    # Only when the policy says FFI must go through hexadeca (upstream rule).
    # Skipping it is also what stops this detector from firing on the literal
    # patterns stored in the file that defines it — hence the \x22 assembly, so
    # no contiguous match for its own pattern exists in this source file
    # (docs/FINDINGS.adoc §F7).
    ffi_alt = ["@cImport", "extern \x22C\x22", "ctypes\\.", "cffi\\.",
               "Foreign\\.C\\.", ":ffi\\b"]
    ffi_pat = Regex(join(ffi_alt, "|"))
    ffi_src = paths_for(by_ext, ["rs", "zig", "py", "hs", "idr", "ex", "erl"])
    ffi_hits = String[]
    if lowercase(String(ffi_method)) == "hexadeca"
        append!(ffi_hits, [p for p in ffi_src if (t = readtext(p)) !== nothing && occursin(ffi_pat, t)])
    end
    if !isempty(ffi_hits)
        all_text = files.paths
        has_hexadeca = any(all_text) do rel
            p = joinpath(root, rel)
            t = readtext(p)
            t !== nothing && occursin(r"hexadeca", t)
        end
        has_hexadeca || record!("DIRECT_FFI_NO_HEXADECA", ffi_hits, :error)
    end

    # ── 6. Idris2 not playing its ABI role ─────────────────────────────────
    idr = get(by_ext, "idr", String[])
    if !isempty(idr)
        has_abi_role = any(vcat(idr, get(by_ext, "md", String[]), get(by_ext, "adoc", String[]))) do p
            t = readtext(p)
            t !== nothing && occursin(r"ABI|Foreign|Layout|idrisiser", t)
        end
        has_abi_role || record!("IDRIS2_NOT_ABI_ROLE", first(idr, 5), :error)
    end

    # ── 7. Nix present (severity configurable; upstream contradicts itself) ─
    nix = vcat([get(by_base, b, String[]) for b in ("flake.nix", "default.nix", "shell.nix")]...)
    record!("NIX_PRESENT", nix, :warn)

    # ── 8. Vite (debate item, never an error) ──────────────────────────────
    vite = String[p for p in vcat(values(by_base)...) if occursin(r"vite\.config\.", lowercase(basename(p)))]
    record!("VITE_DEBATE", unique(vite), :warn)

    if files.truncated
        push!(notes, "walk truncated at max_files=$(files.considered): anti-pattern absence is NOT proof of absence")
    end
    if !isempty(files.unreadable)
        push!(notes, "unreadable directories: $(length(files.unreadable))")
    end

    return Findings(errors = unique(errs), warnings = unique(warns), notes = notes, evidence = ev)
end

end # module
