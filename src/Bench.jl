# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
"""
    Bench

Repetition-based timing with median/MAD, for the "evaluation and benchmarking"
half of this repo's remit.

This exists because `metadatastician/cadastra@verification/benchmarks/` is a
3-line stub (`= Benchmarks Unit`) and `benches/template_bench.sh` measures
nothing reproducible — see `docs/FINDINGS.adoc` §F6. Deliberate choices:

* median + median absolute deviation, never mean ± stddev: a warm-up-free mean
  on a shared runner is dominated by outliers, and an outlier is exactly what a
  CI box produces.
* warm-up reps are discarded before the first sample is recorded.
* GC is run before each sample, and allocated bytes are captured per sample, so
  an allocation regression is visible as such instead of showing up as "slow".
* the harness reports the environment (Julia VERSION, word size, threads) with
  every result, because a number without its environment is not a measurement.
"""
module Bench

import ..Languages, ..Detect, ..Classify, ..Policy

export Result, measure, median, mad, compare, compare_medians, summary_line
export to_json, to_csv_row, bench_analyser

struct Result
    name::String
    reps::Int
    warmup::Int
    times_ns::Vector{Float64}
    median_ns::Float64
    mad_ns::Float64
    min_ns::Float64
    max_ns::Float64
    bytes_per_rep::Float64
    julia_version::String
    word_size::Int
    threads::Int
end

function median(v::AbstractVector{<:Real})
    isempty(v) && return NaN
    s = sort(collect(v))
    n = length(s)
    return isodd(n) ? Float64(s[(n + 1) ÷ 2]) : 0.5 * (Float64(s[n ÷ 2]) + Float64(s[n ÷ 2 + 1]))
end

"Median absolute deviation around the supplied median (upstream-style ×1.4826 normalisation left to the caller)."
function mad(v::AbstractVector{<:Real}, med = median(v))
    isempty(v) && return NaN
    return median([abs(x - med) for x in v])
end

"""Time one call to `f`; return `(nanoseconds, allocated_bytes)`.

Allocation accounting is best-effort: `Base.gc_num()` is not a documented API,
so when it is unavailable the byte count reads `0.0` and the timing is still
real. A missing number is reported as missing, never as zero-cost.
"""
function timed_call(f)
    g0 = try
        Base.gc_num()
    catch
        nothing
    end
    t0 = time_ns()
    f()
    t1 = time_ns()
    bytes = 0.0
    if g0 !== nothing
        g1 = try
            Base.gc_num()
        catch
            nothing
        end
        if g1 !== nothing
            bytes = Float64(g1.allocd - g0.allocd)
        end
    end
    return Float64(t1 - t0), bytes
end

"""
    measure(f; name = "unnamed", reps = 11, warmup = 3) -> Result

Run `f` `warmup + reps` times; keep only the timed reps. `reps` is odd by
default so the median is an observed sample rather than an interpolation.
"""
function measure(f; name::AbstractString = "unnamed", reps::Integer = 11, warmup::Integer = 3)
    r = max(1, Int(reps))
    w = max(0, Int(warmup))
    for i in 1:w
        f()
    end
    times = Float64[]
    bytes = Float64[]
    for i in 1:r
        try
            GC.gc()
        catch
            nothing
        end
        t, b = timed_call(f)
        push!(times, t)
        push!(bytes, b)
    end
    med = median(times)
    return Result(String(name), r, w, times, med, mad(times, med),
                  minimum(times), maximum(times), median(bytes),
                  string(VERSION), Sys.WORD_SIZE, Threads.nthreads())
end

"`ratio = other / this`; >1 means the other measurement is slower."
function compare_medians(this_ns::Real, other_ns::Real; tol::Real = 0.10)
    t = Float64(this_ns)
    o = Float64(other_ns)
    if !(isfinite(t) && isfinite(o)) || t <= 0
        return (ratio = NaN, verdict = :unknown, tol = Float64(tol))
    end
    ratio = o / t
    verdict = if ratio > 1 + tol
        :slower
    elseif ratio < 1 - tol
        :faster
    else
        :within_tolerance
    end
    return (ratio = ratio, verdict = verdict, tol = Float64(tol))
end

"`compare(a, b)` — b judged against a as the baseline."
function compare(a::Result, b::Result; tol::Float64 = 0.10)
    return compare_medians(a.median_ns, b.median_ns; tol = tol)
end

"""One CSV line per result, so a baseline is a file rather than a JSON parse."""
function to_csv_row(res::Result)
    return join((res.name, res.reps, res.warmup, res.median_ns, res.mad_ns, res.min_ns,
                 res.max_ns, res.bytes_per_rep, res.julia_version, res.word_size, res.threads), ",")
end

const CSV_HEADER = "name,reps,warmup,median_ns,mad_ns,min_ns,max_ns,bytes_per_rep,julia,word_size,threads"

function summary_line(res::Result)
    return string(res.name, ": median ", round(res.median_ns / 1e6; digits = 3), " ms",
                  " (MAD ", round(res.mad_ns / 1e6; digits = 3), " ms; ",
                  "n=", res.reps, ", warmup=", res.warmup,
                  ", ", round(res.bytes_per_rep / 1024; digits = 1), " KiB/rep",
                  ", julia ", res.julia_version, ", ", res.threads, " threads)")
end

json_escape(s::AbstractString) = replace(s, "\\" => "\\\\", "\"" => "\\\"")

"`to_json(res)` — one JSON object, hand-written because stdlib `Base.JSON` only parses."
function to_json(res::Result)
    times = join(string.(round.(res.times_ns; digits = 0)), ", ")
    return string("{\n  \"name\": \"", json_escape(res.name), "\",\n",
                  "  \"median_ns\": ", res.median_ns, ",\n",
                  "  \"mad_ns\": ", res.mad_ns, ",\n",
                  "  \"min_ns\": ", res.min_ns, ",\n",
                  "  \"max_ns\": ", res.max_ns, ",\n",
                  "  \"bytes_per_rep\": ", res.bytes_per_rep, ",\n",
                  "  \"reps\": ", res.reps, ",\n",
                  "  \"warmup\": ", res.warmup, ",\n",
                  "  \"times_ns\": [", times, "],\n",
                  "  \"julia\": \"", res.julia_version, "\",\n",
                  "  \"word_size\": ", res.word_size, ",\n",
                  "  \"threads\": ", res.threads, "\n}\n")
end

"""
    bench_analyser(root::AbstractString; reps = 7, max_files = 200_000) -> Vector{Result}

Time the console's own work on `root`: the walk, the detector pass, and a full
assess. This is the dogfood benchmark — the analyser measuring itself, so a
change to the policy tables has a number attached to it.
"""
function bench_analyser(root::AbstractString; reps::Integer = 7, max_files::Integer = 200_000)
    isdir(root) || error("not a directory: $root")
    pol = Policy.load(root)
    results = Result[]
    push!(results, measure(; name = "walk", reps = reps) do
        Languages.walk(root; max_files = max_files)
        nothing
    end)
    files = Languages.walk(root; max_files = max_files)
    push!(results, measure(; name = "detect", reps = reps) do
        Detect.analyse(root, files; nix_severity = pol.nix_severity)
        nothing
    end)
    push!(results, measure(; name = "assess", reps = reps) do
        Classify.assess(root; max_files = max_files)
        nothing
    end)
    return results
end

end # module
