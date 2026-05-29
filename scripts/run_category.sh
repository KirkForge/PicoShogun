#!/bin/bash
# Shogun Enterprise Batch Runner
# Executes project categories with full logging, health checks, and DB tracking

set -euo pipefail

BASE="/home/kirk/.picoclaw/workspace"
HIVE="$BASE/Hivemind-projects"
LOGS="$BASE/Shogun/logs"
DB="$BASE/Shogun/shogun.db"
PYTHON="python3"

mkdir -p "$LOGS"

usage() {
    echo "Usage: $0 <category> [options]"
    echo "Categories: monitoring defense offense analysis crypto training infrastructure"
    echo "Options:"
    echo "  --timeout=N        Override default timeout (seconds)"
    echo "  --parallel=N       Run N projects concurrently"
    echo "  --no-db            Skip database logging"
    echo "  --dry-run          Show what would run without executing"
    echo "  --verbose          Show all output"
    exit 1
}

category=""
timeout=300
parallel=1
use_db=1
dry_run=0
verbose=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout=*) timeout="${1#*=}" ;;
        --parallel=*) parallel="${1#*=}" ;;
        --no-db) use_db=0 ;;
        --dry-run) dry_run=1 ;;
        --verbose) verbose=1 ;;
        monitoring|defense|offense|analysis|crypto|training|infrastructure)
            category="$1" ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

if [[ -z "$category" ]]; then
    usage
fi

echo "=== Shogun Enterprise Batch Runner ==="
echo "Category: $category"
echo "Timeout: ${timeout}s"
echo "Parallel: $parallel"
echo "Database: $([[ $use_db -eq 1 ]] && echo 'enabled' || echo 'disabled')"
echo "Dry run: $([[ $dry_run -eq 1 ]] && echo 'yes' || echo 'no')"
echo ""

# Category matching patterns
declare -A PATTERNS
PATTERNS[monitoring]="sniffer|monitor|detection|scanner|anomaly|ids|honeypot|darkweb|threat|camera|insider|dns|attack"
PATTERNS[defense]="firewall|secure|encryption|honeypot|antivirus|tls|waf|auth|factor|boot|disk|segmentation|header|email|datacenter|container|devops|supply-chain|architecture|biometric"
PATTERNS[offense]="cracker|phishing|vuln|exploit|ddos|red-team|social|mobile|shellcode|privesc|bug|wireless|api|gpu|ctf|factor|password"
PATTERNS[analysis]="forensics|malware|rootkit|sandbox|binary|steganography|embedded|vehicle|ics|memory"
PATTERNS[crypto]="encrypt|wallet|pki|messaging|cryptography|tor"
PATTERNS[infrastructure]="lab|routing|active-directory|cloud"
PATTERNS[training]="ctf|training|challenge"

log_batch() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $msg" >> "$LOGS/batch.log"
    if [[ $verbose -eq 1 ]]; then
        echo "$msg"
    fi
}

# Find matching projects
PROJECTS=()
for proj_dir in "$HIVE"/*/; do
    proj_name=$(basename "$proj_dir")
    if [[ "$proj_name" =~ ${PATTERNS[$category]} ]]; then
        # Find main script
        script=""
        if compgen -G "$proj_dir"*.py > /dev/null 2>>1; then
            script=$(find "$proj_dir" -maxdepth 1 -name "*.py" | head -1)
        elif compgen -G "$proj_dir"*.sh > /dev/null 2>>1; then
            script=$(find "$proj_dir" -maxdepth 1 -name "*.sh" | head -1)
        fi
        
        if [[ -n "$script" ]]; then
            PROJECTS+=("$proj_name:$script")
        fi
    fi
done

total=${#PROJECTS[@]}
echo "Found $total projects in category '$category'"
echo ""

if [[ $total -eq 0 ]]; then
    echo "No projects found"
    exit 0
fi

if [[ $dry_run -eq 1 ]]; then
    echo "=== DRY RUN - Would execute: ==="
    for entry in "${PROJECTS[@]}"; do
        IFS=':' read -r name script <<< "$entry"
        echo "  $name: $script"
    done
    exit 0
fi

log_batch "BATCH_START | category=$category | projects=$total | time=$(date +%s)"

# Track results
completed=0
failed=0
timeouts=0

run_project() {
    local entry="$1"
    IFS=':' read -r proj_name script <<< "$entry"
    local script_name=$(basename "$script")
    local proj_dir=$(dirname "$script")
    
    log_batch "RUN_START | $proj_name"
    
    local start=$(date +%s)
    local output=""
    local exit_code=0
    
    if [[ $use_db -eq 1 ]]; then
        sqlite3 "$DB" "INSERT INTO project_runs (project_id, run_start, status) VALUES ('${proj_name}', datetime('now'), 'running');"
    fi
    
    if [[ "$script" == *.py ]]; then
        output=$(cd "$proj_dir" 2>/dev/null && timeout "$timeout" "$PYTHON" "$script_name" 2>&1) || exit_code=$?
    else
        output=$(cd "$proj_dir" 2>/dev/null && timeout "$timeout" bash "$script_name" 2>&1) || exit_code=$?
    fi
    
    local end=$(date +%s)
    local duration=$((end - start))
    
    if [[ $exit_code -eq 0 ]]; then
        status="completed"
        ((completed++))
    elif [[ $exit_code -eq 124 ]]; then
        status="timeout"
        ((timeouts++))
    else
        status="failed"
        ((failed++))
    fi
    
    # Truncate for DB
    local output_trunc="${output:0:10000}"
    
    if [[ $use_db -eq 1 ]]; then
        sqlite3 "$DB" "UPDATE project_runs SET run_end=datetime('now'), status='${status}', exit_code=${exit_code}, output='$(echo "$output_trunc" | sed "s/'/''/g")', duration_seconds=${duration} WHERE project_id='${proj_name}' AND status='running';"
    fi
    
    log_batch "RUN_END | $proj_name | status=$status | exit=$exit_code | duration=${duration}s"
    
    # Save full output to log file
    echo "$output" > "$LOGS/${proj_name}.log"
    
    if [[ $verbose -eq 1 ]]; then
        echo "[$status] $proj_name (${duration}s)"
        if [[ $exit_code -ne 0 ]]; then
            echo "  Output: ${output:0:500}"
        fi
    fi
}

# Run projects
if [[ $parallel -gt 1 ]]; then
    # Parallel execution using background jobs
    for entry in "${PROJECTS[@]}"; do
        run_project "$entry" &
        # Limit concurrent jobs
        while [[ $(jobs -r | wc -l) -ge $parallel ]]; do
            sleep 0.1
        done
    done
    wait
else
    # Sequential execution
    for entry in "${PROJECTS[@]}"; do
        run_project "$entry"
    done
fi

# Summary
log_batch "BATCH_END | category=$category | completed=$completed | failed=$failed | timeouts=$timeouts"

echo ""
echo "=== Batch Complete ==="
echo "Completed: $completed"
echo "Failed:    $failed"
echo "Timeouts:  $timeouts"
echo "Total:     $total"
echo ""
echo "Logs: $LOGS/"
