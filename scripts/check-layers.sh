#!/bin/sh
# Fails if an import crosses the layers of docs/ARCHITECTURE.md section 1. The
# core imports only the system modules below, and the vault and the engine
# only with `internal import`. The app imports neither the vault nor the
# engine. A clean build refuses some of these, an incremental build may not.
set -eu
cd "$(dirname "$0")/.."

core=Packages/CypherCore/Sources
app=App
for folder in "$core" "$app"; do
    if [ ! -d "$folder" ]; then
        echo "error: $folder is missing, so its imports cannot be checked" >&2
        exit 1
    fi
done

# Every import in a folder's Swift files, one per line: "file:line access module".
# Attributes, with or without arguments, are skipped; the access is "default"
# when none is written.
imports() {
    find "$1" -name '*.swift' -exec awk '
        {
            line = $0
            sub(/^[ \t]+/, "", line)
            while (match(line, /^@[A-Za-z_][A-Za-z0-9_]*(\([^)]*\))?[ \t]+/)) line = substr(line, RLENGTH + 1)
            access = "default"
            if (match(line, /^(public|package|internal|fileprivate|private)[ \t]+/)) {
                access = substr(line, 1, RLENGTH)
                sub(/[ \t]+$/, "", access)
                line = substr(line, RLENGTH + 1)
            }
            if (line !~ /^import[ \t]/) next
            sub(/^import[ \t]+/, "", line)
            if (match(line, /^(typealias|struct|class|enum|protocol|let|var|func)[ \t]+/)) line = substr(line, RLENGTH + 1)
            module = line
            sub(/[.; \t].*$/, "", module)
            print FILENAME ":" FNR " " access " " module
        }' {} +
}

failed=0
fail() {
    echo "$1" >&2
    failed=1
}

core_imports=$(imports "$core")
[ -n "$core_imports" ] || fail "error: no imports found in $core"
while read -r place access module; do
    case "$module" in
        Foundation | Observation | CryptoKit | os | Synchronization) ;;
        Vault | Stores | Sealing | CypherEngine)
            case "$access" in
                internal | fileprivate | private) ;;
                *) fail "$place: the core imports $module without \`internal import\`" ;;
            esac
            ;;
        *) fail "$place: the core may not import $module" ;;
    esac
done <<EOF
$core_imports
EOF

app_imports=$(imports "$app")
while read -r place access module; do
    case "$module" in
        Vault | Stores | Sealing | VaultTestSupport | CypherEngine* | cypher_engine*)
            fail "$place: the app imports $module; it may import only CypherCore of the packages" ;;
    esac
done <<EOF
$app_imports
EOF

exit "$failed"
