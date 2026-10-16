#!/bin/sh
#################################################################################
#
#   Lynis Report Converter (JSON & SARIF)
# ----------------------------------------
#
# Converts Lynis report files (lynis-report.dat) into standard JSON and
# SARIF v2.1.0 (Static Analysis Results Interchange Format) for CI/CD,
# GitHub Code Scanning, GitLab Security Dashboard, and SIEM ingestion.
#
#################################################################################

INPUT_FILE=""
OUTPUT_FILE=""
FORMAT="json"

show_help() {
    cat << 'EOF'
Usage: lynis-report-converter.sh [options]

Options:
  -i <file>       Path to lynis-report.dat (default: /var/log/lynis-report.dat)
  -o <file>       Output file (default: stdout)
  -f <format>     Output format: 'json' or 'sarif' (default: json)
  --to-json [out] Shortcut for -f json with optional output file
  --to-sarif [out] Shortcut for -f sarif with optional output file
  -h, --help      Show this help message

Examples:
  ./lynis-report-converter.sh -i /var/log/lynis-report.dat -f json -o report.json
  ./lynis-report-converter.sh -i /var/log/lynis-report.dat -f sarif -o report.sarif
EOF
}

# Parse arguments
while [ $# -ge 1 ]; do
    case "$1" in
        -i)
            shift
            INPUT_FILE="$1"
        ;;
        -o)
            shift
            OUTPUT_FILE="$1"
        ;;
        -f)
            shift
            FORMAT="$1"
        ;;
        --to-json)
            FORMAT="json"
            if [ $# -gt 1 ] && [ "$(echo "$2" | cut -c1)" != "-" ]; then
                shift
                OUTPUT_FILE="$1"
            fi
        ;;
        --to-sarif)
            FORMAT="sarif"
            if [ $# -gt 1 ] && [ "$(echo "$2" | cut -c1)" != "-" ]; then
                shift
                OUTPUT_FILE="$1"
            fi
        ;;
        -h|--help)
            show_help
            exit 0
        ;;
        *)
            echo "Unknown argument: $1" >&2
            show_help >&2
            exit 1
        ;;
    esac
    shift
done

# Locate default input file if not specified
if [ -z "${INPUT_FILE}" ]; then
    if [ -n "${REPORTFILE}" ] && [ -f "${REPORTFILE}" ]; then
        INPUT_FILE="${REPORTFILE}"
    elif [ -f "./lynis-report.dat" ]; then
        INPUT_FILE="./lynis-report.dat"
    elif [ -f "/var/log/lynis-report.dat" ]; then
        INPUT_FILE="/var/log/lynis-report.dat"
    elif [ -f "/tmp/lynis-report.dat" ]; then
        INPUT_FILE="/tmp/lynis-report.dat"
    else
        echo "Error: No input report file found. Specify with -i <path>" >&2
        exit 1
    fi
fi

if [ ! -f "${INPUT_FILE}" ]; then
    echo "Error: Input file '${INPUT_FILE}' does not exist." >&2
    exit 1
fi

# Prefer Python if available for rock-solid JSON/SARIF serialization
PYTHON_BIN=""
if command -v python3 > /dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python > /dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
fi

if [ -n "${PYTHON_BIN}" ]; then
    "${PYTHON_BIN}" - "${INPUT_FILE}" "${FORMAT}" "${OUTPUT_FILE}" << 'PYEOF'
import sys
import json
import os

input_file = sys.argv[1]
format_type = sys.argv[2].lower()
output_file = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None

data = {
    "report_meta": {},
    "warnings": [],
    "suggestions": [],
    "report_data": {}
}

with open(input_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        val = val.strip()

        if key == "warning[]":
            parts = val.split("|")
            test_id = parts[0] if len(parts) > 0 else ""
            msg = parts[1] if len(parts) > 1 else ""
            details = parts[2] if len(parts) > 2 else ""
            solution = parts[3] if len(parts) > 3 else ""
            data["warnings"].append({
                "test_id": test_id,
                "message": msg,
                "details": details,
                "solution": solution
            })
        elif key == "suggestion[]":
            parts = val.split("|")
            test_id = parts[0] if len(parts) > 0 else ""
            msg = parts[1] if len(parts) > 1 else ""
            details = parts[2] if len(parts) > 2 else ""
            solution = parts[3] if len(parts) > 3 else ""
            data["suggestions"].append({
                "test_id": test_id,
                "message": msg,
                "details": details,
                "solution": solution
            })
        elif key.endswith("[]"):
            clean_key = key[:-2]
            if clean_key not in data["report_data"]:
                data["report_data"][clean_key] = []
            if isinstance(data["report_data"][clean_key], list):
                data["report_data"][clean_key].append(val)
        else:
            data["report_data"][key] = val

meta_keys = [
    "lynis_version", "program_name", "os_name", "os_fullname",
    "os_version", "hostname", "scan_mode", "hardening_index",
    "tests_executed", "total_warnings", "total_suggestions", "scan_date"
]
for k in meta_keys:
    if k in data["report_data"]:
        data["report_meta"][k] = data["report_data"][k]

result_str = ""

if format_type == "sarif":
    rules_dict = {}
    sarif_results = []

    def get_rule_entry(test_id, default_msg):
        if test_id not in rules_dict:
            rules_dict[test_id] = {
                "id": test_id,
                "name": test_id,
                "shortDescription": {"text": default_msg or f"Security check {test_id}"},
                "helpUri": f"https://cisofy.com/lynis/controls/{test_id}/" if test_id else "https://cisofy.com/lynis/"
            }
        return test_id

    for w in data["warnings"]:
        tid = get_rule_entry(w["test_id"], w["message"])
        msg_text = w["message"]
        if w["details"] and w["details"] != "-":
            msg_text += f" (Details: {w['details']})"
        if w["solution"] and w["solution"] != "-":
            msg_text += f" [Solution: {w['solution']}]"
        sarif_results.append({
            "ruleId": tid,
            "level": "error",
            "message": {"text": msg_text}
        })

    for s in data["suggestions"]:
        tid = get_rule_entry(s["test_id"], s["message"])
        msg_text = s["message"]
        if s["details"] and s["details"] != "-":
            msg_text += f" (Details: {s['details']})"
        if s["solution"] and s["solution"] != "-":
            msg_text += f" [Solution: {s['solution']}]"
        sarif_results.append({
            "ruleId": tid,
            "level": "note",
            "message": {"text": msg_text}
        })

    version_str = str(data["report_data"].get("lynis_version", "3.1.8"))

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lynis",
                        "version": version_str,
                        "informationUri": "https://cisofy.com/lynis/",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }
    result_str = json.dumps(sarif_doc, indent=2)
else:
    result_str = json.dumps(data, indent=2)

if output_file:
    with open(output_file, "w", encoding="utf-8") as out:
        out.write(result_str + "\n")
else:
    print(result_str)
PYEOF
    exit $?
fi

# Fallback: POSIX AWK implementation for systems without Python
awk -v format="${FORMAT}" -v outfile="${OUTPUT_FILE}" '
BEGIN {
    FS = "="
    w_count = 0
    s_count = 0
    d_count = 0
}
{
    line = $0
    sub(/^[ \t]+/, "", line)
    sub(/[ \t]+$/, "", line)
    if (line == "" || substr(line, 1, 1) == "#") next
    idx = index(line, "=")
    if (idx == 0) next
    k = substr(line, 1, idx - 1)
    v = substr(line, idx + 1)

    gsub(/\\/, "\\\\", v)
    gsub(/"/, "\\\"", v)

    if (k == "warning[]") {
        warnings[w_count++] = v
    } else if (k == "suggestion[]") {
        suggestions[s_count++] = v
    } else {
        d_keys[d_count] = k
        d_vals[d_count] = v
        d_count++
    }
}
END {
    if (format == "sarif") {
        res = "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n          \"name\": \"Lynis\",\n          \"version\": \"3.1.8\",\n          \"informationUri\": \"https://cisofy.com/lynis/\"\n        }\n      },\n      \"results\": [\n"
        first = 1
        for (i = 0; i < w_count; i++) {
            n = split(warnings[i], parts, "|")
            tid = parts[1]
            msg = parts[2]
            if (parts[3] != "" && parts[3] != "-") msg = msg " (" parts[3] ")"
            if (!first) res = res ",\n"
            first = 0
            res = res "        {\n          \"ruleId\": \"" tid "\",\n          \"level\": \"error\",\n          \"message\": {\"text\": \"" msg "\"}\n        }"
        }
        for (i = 0; i < s_count; i++) {
            n = split(suggestions[i], parts, "|")
            tid = parts[1]
            msg = parts[2]
            if (parts[3] != "" && parts[3] != "-") msg = msg " (" parts[3] ")"
            if (!first) res = res ",\n"
            first = 0
            res = res "        {\n          \"ruleId\": \"" tid "\",\n          \"level\": \"note\",\n          \"message\": {\"text\": \"" msg "\"}\n        }"
        }
        res = res "\n      ]\n    }\n  ]\n}"
    } else {
        res = "{\n  \"warnings\": [\n"
        for (i = 0; i < w_count; i++) {
            split(warnings[i], parts, "|")
            if (i > 0) res = res ",\n"
            res = res "    {\"test_id\": \"" parts[1] "\", \"message\": \"" parts[2] "\", \"details\": \"" parts[3] "\", \"solution\": \"" parts[4] "\"}"
        }
        res = res "\n  ],\n  \"suggestions\": [\n"
        for (i = 0; i < s_count; i++) {
            split(suggestions[i], parts, "|")
            if (i > 0) res = res ",\n"
            res = res "    {\"test_id\": \"" parts[1] "\", \"message\": \"" parts[2] "\", \"details\": \"" parts[3] "\", \"solution\": \"" parts[4] "\"}"
        }
        res = res "\n  ],\n  \"report_data\": {\n"
        for (i = 0; i < d_count; i++) {
            if (i > 0) res = res ",\n"
            res = res "    \"" d_keys[i] "\": \"" d_vals[i] "\""
        }
        res = res "\n  }\n}"
    }

    if (outfile != "") {
        print res > outfile
    } else {
        print res
    }
}
' "${INPUT_FILE}"

