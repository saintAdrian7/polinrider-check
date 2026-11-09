#!/usr/bin/env bash
#
# PolinRider check — scans a folder, its git repositories and this machine for
# the PolinRider / TasksJacker malware. Read-only: it changes nothing.
#
#   ./scan.sh                 scan the current folder
#   ./scan.sh ~/Projects      scan a folder
#   ./scan.sh ~/Projects --remote   also scan every remote branch (fetches first)
#   ./scan.sh ~/Projects --skip-machine
#
# Exit codes: 0 clean, 1 findings, 2 bad path.
# Needs bash 4+, grep, awk, find, git. macOS: `brew install bash grep` is not
# required, but GNU grep is used when available (ggrep).

set -u
VERSION="2.0.0"

ROOT=""
REMOTE=0
SKIP_MACHINE=0
for a in "$@"; do
  case "$a" in
    --remote) REMOTE=1 ;;
    --skip-machine) SKIP_MACHINE=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) ROOT="$a" ;;
  esac
done
ROOT="${ROOT:-$PWD}"
[ -d "$ROOT" ] || { echo "Folder not found: $ROOT" >&2; exit 2; }
ROOT="$(cd "$ROOT" && pwd)"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

GREP=grep
command -v ggrep >/dev/null 2>&1 && GREP=ggrep

# ---------------------------------------------------------------- indicators

# Exact strings from known builds; the structural checks catch new builds.
SIG_LITERALS=(
  '("rmcej%otb%",2857687)'
  "global['!']='8-"
  '("Cot%3t=shtP",1111436)'
  "global['_V']='8-"
  'global.i="A10'
)
# Traits shared across builds (extended regex).
SIG_REGEX='global[[:space:]]*\.[[:space:]]*i[[:space:]]*=[[:space:]]*["'"'"']A[0-9]+|global[[:space:]]*\[[[:space:]]*["'"'"'][^"'"'"']{1,4}["'"'"'][[:space:]]*\][[:space:]]*=[[:space:]]*["'"'"'][0-9]+-|global[[:space:]]*\[[[:space:]]*["'"'"']r["'"'"'][[:space:]]*\][[:space:]]*=[[:space:]]*require|\)\)[[:space:]]*;[[:space:]]*\}[[:space:]]*run[[:space:]]*\([[:space:]]*\)[[:space:]]*;?[[:space:]]*$'
MIN_PAYLOAD_LINE=2000
MIN_PADDING_RUN=200

REPO_ARTIFACTS=(temp_auto_push.bat temp_interactive_push.bat config.bat branch_structure.json)
GITIGNORE_INJECTED='^[[:space:]]*(config\.bat|temp-auto\.bat|temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)[[:space:]]*$'

C2_HOSTS=(260120.vercel.app default-configuration.vercel.app vscode-settings-bootstrap.vercel.app vscode-settings-config.vercel.app vscode-bootstrapper.vercel.app vscode-load-config.vercel.app)
STAKINGGAME_UUID="e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"

MALICIOUS_PACKAGES=(tailwindcss-style-animate tailwind-mainanimation tailwind-autoanimation tailwind-animationbased tailwindcss-typography-style tailwindcss-style-modify tailwindcss-animate-style)

NPM_CLI_MAX_CLEAN_BYTES=5000
PRUNE='-name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name coverage -o -name .cache -o -name vendor'

# ---------------------------------------------------------------- output

FINDINGS=0
if [ -t 1 ]; then RED=$'\e[31m'; GREEN=$'\e[32m'; CYAN=$'\e[36m'; DIM=$'\e[2m'; NC=$'\e[0m'; else RED=""; GREEN=""; CYAN=""; DIM=""; NC=""; fi
finding() { FINDINGS=$((FINDINGS+1)); printf '  %s[!]%s %s  -  %s%s%s\n' "$RED" "$NC" "$1" "$RED" "$2" "$NC"; }
section() { printf '\n%s%s%s\n' "$CYAN" "$1" "$NC"; }
clean_if() { [ "$FINDINGS" -eq "$1" ] && printf '  %sclean%s\n' "$GREEN" "$NC"; }

# ---------------------------------------------------------------- content checks

# find_payload <file> <display name>  → prints a description or nothing
find_payload() {
  local f="$1" name="$2" hits=""
  for lit in "${SIG_LITERALS[@]}"; do
    $GREP -qF -- "$lit" "$f" 2>/dev/null && hits="${hits}signature '$lit'; "
  done
  $GREP -qE -- "$SIG_REGEX" "$f" 2>/dev/null && hits="${hits}family trait; "
  local long
  long=$(awk -v min="$MIN_PAYLOAD_LINE" -v pad="$MIN_PADDING_RUN" '
    length($0) >= min {
      s = $0; if (match(s, / {200,}[^ ]/)) { print NR ":" length($0); exit }
    }' "$f" 2>/dev/null)
  [ -n "$long" ] && hits="${hits}line ${long%%:*} is ${long##*:} chars, hidden behind whitespace padding; "
  case "$name" in
    *.mjs|*.config.js|*.config.ts)
      $GREP -qE 'createRequire[[:space:]]*\([[:space:]]*import\.meta\.url[[:space:]]*\)' "$f" 2>/dev/null && hits="${hits}createRequire(import.meta.url) shim; " ;;
  esac
  [ -n "$hits" ] && printf '%s' "${hits%; }"
}

is_binary() { LC_ALL=C head -c 8000 "$1" | tr -d '\0' | cmp -s - <(LC_ALL=C head -c 8000 "$1") && return 1 || return 0; }
is_real_font() {
  local m; m=$(LC_ALL=C head -c 4 "$1" | od -An -c | tr -d ' \n')
  case "$m" in wOF2|wOFF|OTTO|true|ttcf) return 0 ;; esac
  [ "$(LC_ALL=C head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = "00010000" ] && return 0
  [ "$(LC_ALL=C dd if="$1" bs=1 skip=34 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "4c50" ] && return 0
  return 1
}

scan_files() {
  section "1. Payload hidden in files"
  local before=$FINDINGS
  while IFS= read -r -d '' f; do
    case "$f" in "$SELF_DIR"/*) continue ;; esac
    [ -s "$f" ] || continue
    [ "$(wc -c < "$f")" -gt $((20*1024*1024)) ] && continue
    case "$f" in
      *.woff|*.woff2|*.ttf|*.otf|*.eot)
        if ! is_real_font "$f" && ! is_binary "$f"; then
          finding "$f" "not a real font: a text file disguised as one ($(wc -c < "$f") bytes). The whole file is the payload."
        fi; continue ;;
      *.md|*.txt|*.lock|*.map|*.svg|*.csv|*.log) continue ;;
    esac
    is_binary "$f" && continue
    local hit; hit=$(find_payload "$f" "$(basename "$f")")
    [ -n "$hit" ] && finding "$f" "$hit"
  done < <(find "$ROOT" \( $PRUNE \) -prune -o -type f -print0 2>/dev/null)
  clean_if "$before"
}

# ---------------------------------------------------------------- repositories

list_repos() {
  find "$ROOT" -name node_modules -prune -o -type d -name .git -print 2>/dev/null | sed 's#/\.git$##'
}

scan_repo_artifacts() {
  section "2. Git repository artifacts ($(printf '%s\n' "$@" | $GREP -c . ) repositories)"
  local before=$FINDINGS
  for repo in "$@"; do
    local had=0
    for a in "${REPO_ARTIFACTS[@]}"; do
      [ -e "$repo/$a" ] && { finding "$repo/$a" "malware file present"; had=1; }
    done
    if [ -f "$repo/.gitignore" ]; then
      while IFS= read -r l; do finding "$repo/.gitignore" "injected line '$l' (hides the malware's files)"; had=1; done \
        < <($GREP -E "$GITIGNORE_INJECTED" "$repo/.gitignore" 2>/dev/null)
    fi
    if [ "$had" -eq 1 ] && git -C "$repo" reflog 2>/dev/null | $GREP -q 'commit (amend)'; then
      finding "$repo" "reflog has amended commits (temp_auto_push.bat amends the last commit with a rewound clock)"
    fi
  done
  clean_if "$before"
}

# ---------------------------------------------------------------- tasks.json / package.json

scan_tasks() {
  section "3. VS Code tasks that run on folder open"
  local before=$FINDINGS
  while IFS= read -r -d '' t; do
    case "$t" in "$SELF_DIR"/*) continue ;; esac
    local hits=""
    for h in "${C2_HOSTS[@]}"; do $GREP -qF "$h" "$t" && hits="${hits}C2 host $h; "; done
    $GREP -qF "$STAKINGGAME_UUID" "$t" && hits="${hits}StakingGame template UUID; "
    if $GREP -q folderOpen "$t"; then
      $GREP -qE 'curl|wget|Invoke-WebRequest|certutil' "$t" && hits="${hits}runs on folderOpen and downloads something; "
      $GREP -qE 'node[[:space:]]+[^"]*\.(woff2?|ttf|eot|otf|png|jpg)' "$t" && hits="${hits}runs on folderOpen and executes a 'font'/'image' file with node; "
      $GREP -qE 'temp_auto_push|config\.bat' "$t" && hits="${hits}runs on folderOpen and calls a malware script; "
    fi
    [ -n "$hits" ] && finding "$t" "${hits%; }"
  done < <(find "$ROOT" -name node_modules -prune -o -type f -path '*/.vscode/tasks.json' -print0 2>/dev/null)
  clean_if "$before"
}

scan_packages() {
  section "4. Malicious npm packages in package.json"
  local before=$FINDINGS
  while IFS= read -r -d '' p; do
    local hits=""
    for m in "${MALICIOUS_PACKAGES[@]}"; do $GREP -qF "\"$m\"" "$p" && hits="${hits}$m, "; done
    [ -n "$hits" ] && finding "$p" "depends on ${hits%, }"
  done < <(find "$ROOT" \( $PRUNE \) -prune -o -type f -name package.json -print0 2>/dev/null)
  clean_if "$before"
}

# ---------------------------------------------------------------- machine

scan_machine() {
  section "5. This machine"
  local before=$FINDINGS
  if command -v npm >/dev/null 2>&1; then
    local prefix cli
    prefix=$(npm prefix -g 2>/dev/null)
    for cli in "$prefix/lib/node_modules/npm/lib/cli.js" "$prefix/node_modules/npm/lib/cli.js" "$(dirname "$(command -v node)")/../lib/node_modules/npm/lib/cli.js"; do
      [ -f "$cli" ] || continue
      local len; len=$(wc -c < "$cli")
      if [ "$len" -gt "$NPM_CLI_MAX_CLEAN_BYTES" ]; then
        finding "$cli" "npm CLI is $len bytes (clean is a few hundred): the malware re-spawns from here on every npm command"
      else
        printf '  %snpm CLI %s is %s bytes, normal%s\n' "$DIM" "$cli" "$len" "$NC"
      fi
      break
    done
    local globals; globals=$(npm ls -g --depth=0 2>/dev/null)
    for m in "${MALICIOUS_PACKAGES[@]}"; do
      printf '%s' "$globals" | $GREP -q " $m@" && finding "npm global" "malicious package $m installed globally"
    done
  else
    printf '  %snpm not found on PATH, skipping npm checks%s\n' "$DIM" "$NC"
  fi
  crontab -l 2>/dev/null | $GREP -qE 'temp_auto_push|\.woff2?|vercel\.app' && finding "crontab" "entry references the malware's files"
  for d in "$HOME/Library/LaunchAgents" "$HOME/.config/autostart" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
      $GREP -qE 'temp_auto_push|\.woff2?|vercel\.app|branch_structure' "$f" 2>/dev/null && finding "$f" "startup item references the malware's files"
    done < <(find "$d" -maxdepth 1 -type f -print0 2>/dev/null)
  done
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    [ -f "$rc" ] && $GREP -qE 'temp_auto_push|vercel\.app|node[[:space:]]+[^ ]*\.woff2?' "$rc" && finding "$rc" "shell startup file references the malware"
  done
  clean_if "$before"
}

# ---------------------------------------------------------------- remote branches

# Blobs are read from git objects via ls-tree SHAs: nothing is checked out, so a
# payload cannot run, and no "ref:path" strings that some shells mangle.
scan_remote() {
  section "6. Remote branches (fetching; this can take a while)"
  local before=$FINDINGS tmp; tmp=$(mktemp)
  for repo in "$@"; do
    [ -n "$(git -C "$repo" remote 2>/dev/null)" ] || continue
    printf '  %s%s%s\n' "$DIM" "$repo" "$NC"
    git -C "$repo" fetch --all --prune --quiet 2>/dev/null
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      case "$ref" in */HEAD) continue ;; esac
      while IFS=$'\t' read -r meta path; do
        [ -n "$path" ] || continue
        case "$path" in */node_modules/*|node_modules/*) continue ;; esac
        local leaf; leaf=$(basename "$path")
        case "$leaf" in
          *.config.js|*.config.mjs|*.config.cjs|*.config.ts|app.js|App.js|index.js|truffle.js|*.woff|*.woff2|.gitignore|tasks.json|package.json|temp_auto_push.bat|temp_interactive_push.bat|config.bat|branch_structure.json) ;;
          *) continue ;;
        esac
        local sha; sha=$(printf '%s' "$meta" | awk '{print $3}')
        local size; size=$(git -C "$repo" cat-file -s "$sha" 2>/dev/null || echo 0)
        [ "$size" -gt 0 ] && [ "$size" -le $((20*1024*1024)) ] || continue
        git -C "$repo" cat-file -p "$sha" > "$tmp" 2>/dev/null || continue
        local where="$repo  $ref : $path"
        case "$leaf" in
          temp_auto_push.bat|temp_interactive_push.bat|config.bat|branch_structure.json) finding "$where" "malware file present on this branch"; continue ;;
          .gitignore) while IFS= read -r l; do finding "$where" "injected line '$l'"; done < <($GREP -E "$GITIGNORE_INJECTED" "$tmp"); continue ;;
          package.json) local hits=""; for m in "${MALICIOUS_PACKAGES[@]}"; do $GREP -qF "\"$m\"" "$tmp" && hits="${hits}$m, "; done; [ -n "$hits" ] && finding "$where" "depends on ${hits%, }"; continue ;;
          tasks.json) $GREP -q folderOpen "$tmp" && $GREP -qE 'curl|wget|node[[:space:]]+[^"]*\.(woff2?|ttf)|vercel\.app' "$tmp" && finding "$where" "task runs on folderOpen and downloads/executes"; continue ;;
          *.woff|*.woff2) if ! is_real_font "$tmp" && ! is_binary "$tmp"; then finding "$where" "text file disguised as a font ($size bytes)"; fi; continue ;;
        esac
        local hit; hit=$(find_payload "$tmp" "$leaf")
        [ -n "$hit" ] && finding "$where" "$hit"
      done < <(git -C "$repo" ls-tree -r "$ref" 2>/dev/null)
    done < <(git -C "$repo" for-each-ref --format='%(refname)' refs/remotes 2>/dev/null)
  done
  rm -f "$tmp"
  clean_if "$before"
}

# ---------------------------------------------------------------- entry point

printf '\nPolinRider check v%s\nScanning %s\n' "$VERSION" "$ROOT"
[ "$REMOTE" -eq 1 ] && echo "Including remote branches"

mapfile -t REPOS < <(list_repos; [ -d "$ROOT/.git" ] && echo "$ROOT")
mapfile -t REPOS < <(printf '%s\n' "${REPOS[@]}" | awk 'NF && !seen[$0]++')

scan_files
scan_repo_artifacts "${REPOS[@]}"
scan_tasks
scan_packages
[ "$SKIP_MACHINE" -eq 0 ] && scan_machine
[ "$REMOTE" -eq 1 ] && scan_remote "${REPOS[@]}"

echo
echo "----------------------------------------"
if [ "$FINDINGS" -gt 0 ]; then
  printf '%sRESULT: %s finding(s)%s\n\n' "$RED" "$FINDINGS" "$NC"
  echo "What to do next: open CLEANUP.md in this folder (or the README on GitHub)."
  echo "Short version: do not open the infected folders in an editor, do not run npm"
  echo "in them, revoke your GitHub tokens and OAuth apps first, then clean."
  exit 1
fi
printf '%sRESULT: clean%s\n' "$GREEN" "$NC"
if [ "$REMOTE" -eq 0 ] && [ "${#REPOS[@]}" -gt 0 ]; then
  echo "Local files are clean. The payload is usually on the REMOTE while the local"
  echo "checkout stays clean, so also run:  ./scan.sh \"$ROOT\" --remote"
fi
exit 0
