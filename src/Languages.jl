# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Languages

Extension → language mapping and the estate's language-policy sets.

Ported from `metadatastician/cadastra` at
`tools/estate-migration-toolkit/scripts/estate-scan.sh` (`BANNED_LANGUAGES`,
`ALLOWED_LANGUAGES`, the `ext_map` associative array), plus the second,
differently-spelled banned list in `ci/language-gate.yml`. The two upstream
lists disagree in spelling (`C#` vs `CSharp`) and `Nix` appears as both banned
and allowed in the scan script; see `docs/FINDINGS.adoc` §F1 and §F2 for the
measurements and the resolution taken here.

Nothing in this module touches the network or shells out, so classification is
reproducible and testable offline.
"""
module Languages

export canonical, language_for_path, walk, has_banned, has_target, banned_present

"""File or directory names that never count as evidence of a language."""
const SKIP_DIRS = Set{String}([
    ".git", ".hg", ".svn", "node_modules", "target", "_build", "vendor",
    ".zig-cache", ".pixi", ".venv", "__pycache__", "build", "dist",
    ".scratch", "Manifest.toml",
])

"""Extension → language, as detected by the upstream scan script."""
const EXT_MAP = Dict{String, String}(
    "rs" => "Rust", "zig" => "Zig", "idr" => "Idris", "hs" => "Haskell",
    "lhs" => "Haskell", "jl" => "Julia", "erl" => "Erlang",
    "hrl" => "Erlang", "ex" => "Elixir", "exs" => "Elixir",
    "go" => "Go", "py" => "Python", "pyi" => "Python",
    "ts" => "TypeScript", "tsx" => "TypeScript", "mts" => "TypeScript",
    "js" => "JavaScript", "jsx" => "JavaScript", "mjs" => "JavaScript",
    "cjs" => "JavaScript", "res" => "ReScript", "resi" => "ReScript",
    "coffee" => "CoffeeScript", "dart" => "Dart", "php" => "PHP",
    "rb" => "Ruby", "pl" => "Perl", "pm" => "Perl", "lua" => "Lua",
    "r" => "R", "R" => "R", "java" => "Java", "kt" => "Kotlin",
    "kts" => "Kotlin", "scala" => "Scala", "sc" => "Scala",
    "cs" => "C#", "fs" => "F#", "fsx" => "F#", "vb" => "Visual Basic",
    "swift" => "Swift", "m" => "Objective-C", "mm" => "Objective-C",
    "v" => "V", "c" => "C", "h" => "C", "cpp" => "C++", "cxx" => "C++",
    "hpp" => "C++", "hh" => "C++", "s" => "Assembly", "S" => "Assembly",
    "asm" => "Assembly", "nix" => "Nix", "ps1" => "PowerShell",
    "psm1" => "PowerShell", "sh" => "Shell", "bash" => "Shell",
    "zsh" => "Shell", "adoc" => "AsciiDoc", "asciidoc" => "AsciiDoc",
    "md" => "Markdown", "markdown" => "Markdown", "tex" => "LaTeX",
    "toml" => "TOML", "yml" => "YAML", "yaml" => "YAML",
    "json" => "JSON", "jsonc" => "JSON", "tf" => "Terraform",
)

"""Basename → language: files with no extension, which the upstream
extension-only map silently ignores (see `docs/FINDINGS.adoc` §F3)."""
const NAME_MAP = Dict{String, String}(
    "makefile" => "Makefile", "gnumakefile" => "Makefile",
    "dockerfile" => "Dockerfile", "containerfile" => "Dockerfile",
    "justfile" => "Just", "gnumakefile.am" => "Makefile",
    "cmakelists.txt" => "CMake",
)

"""Languages the estate forbids in repository code.

Spelling is normalised to GitHub linguist's names, so both upstream variants
(`C#` and `CSharp`) are accepted on input; only the canonical form is emitted.
"""
const BANNED = Set{String}([
    "Go", "Python", "Nix", "JavaScript", "TypeScript", "ReScript",
    "CoffeeScript", "Dart", "PHP", "Ruby", "Perl", "Lua", "R",
    "Objective-C", "Swift", "Kotlin", "Java", "Scala", "Groovy",
    "C#", "F#", "Visual Basic", "PowerShell", "CMake", "Terraform",
])

"""Languages of the target stack."""
const ALLOWED = Set{String}([
    "Rust", "Zig", "Idris", "Haskell", "Julia", "Erlang", "Elixir",
    "Shell", "Makefile", "Dockerfile", "Just", "AsciiDoc", "Markdown",
    "LaTeX", "TOML", "YAML", "JSON", "C", "C++", "Assembly",
])

"""Languages in `BANNED` whose ban severity is downgraded by default.

`Nix` is banned for application code but permitted inside CI configuration,
which a language-by-extension scan cannot tell apart. `CMake`/`Terraform` are
not in the upstream ban list at all; they are listed here as ban-warning
candidates only, never as hard failures, because the estate has no ruling on
them (see `docs/FINDINGS.adoc` §F2).
"""
const WARN_ONLY = Set{String}(["Nix", "CMake", "Terraform"])

"""
    canonical(lang::AbstractString) -> String

Fold the upstream spelling variants onto one name.
"""
function canonical(lang::AbstractString)
    s = String(lang)
    if s == "CSharp"
        return "C#"
    elseif s == "FSharp"
        return "F#"
    elseif s == "VisualBasic"
        return "Visual Basic"
    elseif s == "Cplusplus" || s == "C++"
        return "C++"
    end
    return s
end

"""
    language_for_path(path::AbstractString) -> Union{String,Nothing}

Language of a single path, by extension then by basename. `nothing` when the
extension is unknown — unknown files are counted, never guessed.
"""
function language_for_path(path::AbstractString)
    base = lowercase(String(basename(path)))
    haskey(NAME_MAP, base) && return NAME_MAP[base]
    ext = String(splitext(path)[2])
    isempty(ext) && return nothing
    ext = startswith(ext, ".") ? ext[2:end] : ext
    # Extension lookup is case-sensitive on purpose: `.R` (R) and `.r` are not
    # the same language, and Julia's `lowercase` would erase the difference.
    haskey(EXT_MAP, ext) && return canonical(EXT_MAP[ext])
    low = lowercase(ext)
    haskey(EXT_MAP, low) && return canonical(EXT_MAP[low])
    return nothing
end

"""Result of walking one repository."""
struct Files
    "Every readable file path found, relative to `root`, first-seen order."
    paths::Vector{String}
    "Distinct languages detected, first-seen order."
    langs::Vector{String}
    "Files attributed to each language."
    counts::Dict{String, Int}
    "Directories walked (i.e. `isdir` was true for them)."
    dirs::Int
    "Files inspected before any cap was hit."
    considered::Int
    "True when the walk stopped early at `max_files`: the inventory is PARTIAL."
    truncated::Bool
    "Paths that could not be read — recorded so a failed scan cannot pass."
    unreadable::Vector{String}
end

Base.isempty(f::Files) = isempty(f.langs)

"""
    walk(root::AbstractString; max_files::Integer = 200_000) -> Files

Enumerate files under `root`, skipping `SKIP_DIRS`, and map them to
languages. `max_files` bounds the walk; when it bites, `truncated` is set
rather than the result being silently clipped (the upstream scan used an
unreported `head -500`, which mis-classifies large repos as clean).

`exclude` lists repository-relative paths to skip wholly. It exists so a
repository can keep its own test fixtures out of its own gate without hiding
them from a direct `walk` of the fixture directory — declared in
`.language-policy.toml`, never assumed.
"""
function walk(root::AbstractString; max_files::Integer = 200_000, exclude = String[])
    excl = [replace(String(e), "\\" => "/") for e in exclude]
    is_excluded(rel) = any(e -> rel == e || startswith(rel, e * "/"), excl)
    paths = String[]
    langs = String[]
    counts = Dict{String, Int}()
    unreadable = String[]
    dirs = 0
    truncated = false
    cap = Int(max_files)

    stack = String[root]
    while !isempty(stack)
        cur = pop!(stack)
        entries = try
            readdir(cur)
        catch e
            if cur != root
                push!(unreadable, relpath(cur, root))
            end
            continue
        end
        dirs += 1
        for name in entries
            full = joinpath(cur, name)
            if isdir(full)
                in(name, SKIP_DIRS) && continue
                length(paths) >= cap && (truncated = true; break)
                push!(stack, full)
                continue
            end
            isfile(full) || continue
            if length(paths) >= cap
                truncated = true
                break
            end
            rel = relpath(full, root)
            is_excluded(rel) && continue
            push!(paths, rel)
            lang = language_for_path(rel)
            lang === nothing && continue
            counts[lang] = get(counts, lang, 0) + 1
            in(lang, langs) || push!(langs, lang)
        end
    end

    return Files(paths, langs, counts, dirs, length(paths), truncated, unreadable)
end

"""`true` when any detected language is in `BANNED`."""
function has_banned(langs::AbstractVector{<:AbstractString})
    return any(lang -> in(canonical(lang), BANNED), langs)
end

"""`true` when any detected language is in `ALLOWED`."""
function has_target(langs::AbstractVector{<:AbstractString})
    return any(lang -> in(canonical(lang), ALLOWED), langs)
end

"""Banned languages present, in input order."""
function banned_present(langs::AbstractVector{<:AbstractString})
    out = String[]
    for lang in langs
        c = canonical(lang)
        if in(c, BANNED) && !in(c, out)
            push!(out, c)
        end
    end
    return out
end

end # module
