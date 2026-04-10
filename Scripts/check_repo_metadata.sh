#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

require_line() {
  local needle="$1"
  local file="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "missing expected line in $file: $needle" >&2
    exit 1
  fi
}

tree_contains_literal() {
  local needle="$1"
  local path="$2"

  if command -v rg >/dev/null 2>&1; then
    rg -Fq -- "$needle" "$path"
  else
    grep -RFq -- "$needle" "$path"
  fi
}

tree_contains_test_function() {
  local test_name="$1"
  local path="$2"
  local pattern="func[[:space:]]+${test_name}([^[:alnum:]_]|$)"

  if command -v rg >/dev/null 2>&1; then
    rg -q -- "$pattern" "$path"
  else
    grep -REq -- "$pattern" "$path"
  fi
}

extract_current_version() {
  local file="$1"
  local symbol="$2"

  ruby -e '
    file, symbol = ARGV
    pattern = /#{Regexp.escape(symbol)}\s*=\s*(\d+)/
    value = nil
    File.foreach(file) do |line|
      if (match = line.match(pattern))
        value = match[1]
        break
      end
    end
    abort("missing version for #{symbol} in #{file}") unless value
    puts value
  ' "$file" "$symbol"
}

shape_pack_version="$(extract_current_version "NuMetal-Q/NuIR/Shape.swift" "public static let currentVersion: UInt16")"
public_seal_proof_version="$(extract_current_version "NuMetal-Q/NuSeal/PublicSealArtifacts.swift" "public static let currentVersion: UInt16")"
seal_proof_version="$(extract_current_version "NuMetal-Q/NuSeal/SpartanProof.swift" "public static let currentVersion: UInt16")"
metal_storage_layout_version="$(extract_current_version "NuMetal-Q/NuMetal/MetalABI.swift" "public static let currentVersion: UInt16")"

require_line "- \`MetalStorageLayout.currentVersion\` is now \`${metal_storage_layout_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`ShapePack.currentVersion\` is now \`${shape_pack_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`SealProof.currentVersion\` is now \`${seal_proof_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`PublicSealProof.currentVersion\` is now \`${public_seal_proof_version}\`." "METAL_FIRST_VNEXT.md"

while IFS= read -r filter; do
  if [[ "$filter" == *"/"* ]]; then
    suite="${filter%%/*}"
    test_name="${filter##*/}"
    if ! tree_contains_test_function "$test_name" "Tests/NuMetal_QTests"; then
      echo "missing documented test function: $filter" >&2
      exit 1
    fi
    if ! tree_contains_literal "$suite" "Tests/NuMetal_QTests"; then
      echo "missing documented test suite: $filter" >&2
      exit 1
    fi
  else
    if ! tree_contains_literal "$filter" "Tests/NuMetal_QTests"; then
      echo "missing documented test suite: $filter" >&2
      exit 1
    fi
  fi
done < <(ruby -e '
  File.foreach("METAL_FIRST_VNEXT.md") do |line|
    next unless line.include?("swift test --filter ")
    filter = line.split("swift test --filter ", 2)[1]
    filter = filter.sub(/`.*$/, "").strip
    puts filter unless filter.empty?
  end
')

echo "Repo metadata checks passed."
