# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Report

The triage report: the same CSV schema the estate's `estate-scan.sh` emits, so
this console can read existing reports and be diffed against them, plus the
counting and summary output.

Two deliberate departures from upstream, both of which matter:

* Upstream counts classes with `grep -c` over the whole CSV line, which also
  matches a description that happens to contain the class name. Counting here
  is per-field.
* Upstream prints classes with a zero count as nothing at all; a class that is
  absent is reported as `0` when `--all-classes` is asked for, so "no KILL
  repos" can be distinguished from "KILL was never measured".
"""
module Report

using ..Classify: Verdict, CLASSES

const HEADER = "source,name,primary_language,all_languages,classification,antipatterns,last_activity,stars_or_commits,forks,description"

const DETECTED = ("NIF_WITHOUT_SNIF", "UNVERIFIED_RUST", "DENO_NOT_BUN", "NODE_NOT_BUN",
                  "DIRECT_FFI_NO_HEXADECA", "IDRIS2_NOT_ABI_ROLE", "NIX_PRESENT", "VITE_DEBATE")

"Field separator used upstream for `all_languages` after the `tr ';' ' '` step."
const LANG_SEP = ' '

function csv_field(x)
    s = x isa AbstractString ? String(x) : string(x)
    needs_quotes = occursin(',', s) || occursin('"', s) || occursin('\n', s) || occursin('\r', s)
    if needs_quotes || s != strip(s)
        return "\"" * replace(s, "\"" => "\"\"") * "\""
    end
    return s
end

function row(v::Verdict)
    return join((csv_field(v.source), csv_field(v.name), csv_field(v.primary_language),
                 csv_field(join(v.languages, LANG_SEP)), csv_field(string(v.classification)),
                 csv_field(join(v.antipatterns, ", ")), csv_field(v.last_activity),
                 csv_field(v.metric), csv_field(v.forks), csv_field(v.description)), ',')
end

"`to_csv(rows)` → the whole document, header first."
to_csv(rows::AbstractVector{Verdict}) = join([HEADER; row.(rows)], "\n") * "\n"

"""
    write_csv(path::AbstractString, rows) -> String

Write the report and return the path. Trailing newline included.
"""
function write_csv(path::AbstractString, rows::AbstractVector{Verdict})
    open(path, "w") do io
        print(io, to_csv(rows))
    end
    return String(path)
end

"""Split one CSV line into fields, honouring doubled-quote quoting (RFC 4180 subset)."""
function split_line(line::AbstractString)
    fields = String[]
    buf = IOBuffer()
    i = 1
    s = String(line)
    n = ncodeunits(s)
    quoted = false
    while i <= n
        c = s[i]
        if quoted
            if c == '"'
                if i < n && nextind(s, i) <= n && s[nextind(s, i)] == '"'
                    print(buf, '"'); i = nextind(s, i)
                else
                    quoted = false
                end
            else
                print(buf, c)
            end
        elseif c == '"'
            quoted = true
        elseif c == ','
            push!(fields, String(take!(buf)))
        else
            print(buf, c)
        end
        i = nextind(s, i)
    end
    push!(fields, String(take!(buf)))
    return fields
end

"""
    read_csv(path::AbstractString) -> (rows::Vector{NamedTuple}, header::Vector{String}, notes::Vector{String})

Load a previously written report (any `estate-triage-report.csv` the estate
already holds). Short rows are padded and noted, never dropped, so a truncated
file cannot masquerade as a clean one.
"""
function read_csv(path::AbstractString)
    lines = split(chomp(String(read(path))), '\n')
    notes = String[]
    if isempty(lines)
        return NamedTuple[], String[], String["empty file: $(path)"]
    end
    header = map(strip, split_line(lines[1]))
    if join(header, ",") != join(split(HEADER, ','), ",")
        push!(notes, "header differs from the estate schema — columns mapped by name where they match")
    end
    rows = NamedTuple[]
    for (idx, line) in enumerate(lines[2:end])
        isempty(strip(line)) && continue
        f = split_line(line)
        if length(f) < length(header)
            push!(notes, "line $(idx + 1) has $(length(f)) of $(length(header)) fields; padded")
            append!(f, fill("", length(header) - length(f)))
        end
        pairs = Pair{Symbol, Any}[]
        for (h, val) in zip(header, f)
            push!(pairs, Symbol(replace(h, ' ' => '_')) => val)
        end
        push!(rows, (; pairs...))
    end
    return rows, header, notes
end

"`Dict(classification => count)` for each row."
function by_class(rows::AbstractVector{Verdict}; all_classes::Bool = false)
    counts = Dict{String, Int}()
    if all_classes
        for c in CLASSES
            counts[string(c)] = 0
        end
    end
    for v in rows
        k = string(v.classification)
        counts[k] = get(counts, k, 0) + 1
    end
    return counts
end

"`Dict(antipattern => count)`, per-field (not `grep -c`)."
function by_pattern(rows::AbstractVector{Verdict})
    counts = Dict{String, Int}(p => 0 for p in DETECTED)
    for v in rows
        for p in unique(v.antipatterns)
            counts[p] = get(counts, p, 0) + 1
        end
    end
    return counts
end

function summary_text(rows::AbstractVector{Verdict}; title = "PROGLANGING SCAN COMPLETE", all_classes = false)
    out = String[]
    bar = "═"^62
    push!(out, bar); push!(out, "  " * title); push!(out, bar); push!(out, "")
    push!(out, "  repositories: $(length(rows))")
    push!(out, "")
    push!(out, "  by classification")
    bc = by_class(rows; all_classes = all_classes)
    if isempty(rows)
        push!(out, "    (no rows — nothing was measured; this is not a pass)")
    end
    for class in (all_classes ? collect(string.(CLASSES)) : sort(collect(keys(bc))))
        c = get(bc, class, 0)
        (c == 0 && !all_classes) && continue
        push!(out, string("    ", rpad(class, 22), c))
    end
    push!(out, "")
    push!(out, "  anti-patterns")
    for (p, c) in sort(collect(by_pattern(rows)); by = kv -> (-kv[2], kv[1]))
        c == 0 && continue
        push!(out, string("    ", rpad(p, 26), c))
    end
    any(v -> v.truncated, rows) && push!(out, "  ⚠ at least one scan was truncated: absence of findings is not proof of absence")
    push!(out, "")
    push!(out, "  Next: review KILL items first, then MIGRATE, then CLEAN.")
    push!(out, bar)
    return join(out, "\n")
end

"Markdown table of rows, for wikis and PR bodies."
function to_markdown(rows::AbstractVector{Verdict})
    out = String[]
    push!(out, "| repo | primary | class | anti-patterns | last activity |")
    push!(out, "|---|---|---|---|---|")
    for v in rows
        push!(out, string("| ", v.name, " | ", v.primary_language, " | ", v.classification,
                          " | ", isempty(v.antipatterns) ? "—" : join(v.antipatterns, "<br>"),
                          " | ", v.last_activity, " |"))
    end
    return join(out, "\n") * "\n"
end

end # module
