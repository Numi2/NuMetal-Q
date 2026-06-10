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

extract_scoped_current_version() {
  local file="$1"
  local type_name="$2"

  ruby -e '
    file, type_name = ARGV
    type_pattern = /^\s*public\s+(?:struct|enum)\s+#{Regexp.escape(type_name)}\b/
    version_pattern = /^\s*public\s+static\s+let\s+currentVersion:\s*UInt16\s*=\s*(\d+)/
    in_type = false
    depth = 0
    value = nil
    File.foreach(file) do |line|
      if !in_type && line.match(type_pattern)
        in_type = true
        depth = line.count("{") - line.count("}")
        next
      end
      next unless in_type
      if (match = line.match(version_pattern))
        value = match[1]
        break
      end
      depth += line.count("{") - line.count("}")
      in_type = false if depth <= 0
    end
    abort("missing currentVersion for #{type_name} in #{file}") unless value
    puts value
  ' "$file" "$type_name"
}

shape_pack_version="$(extract_scoped_current_version "NuMetal-Q/NuIR/Shape.swift" "ShapePack")"
public_seal_proof_version="$(extract_scoped_current_version "NuMetal-Q/NuSeal/PublicSealArtifacts.swift" "PublicSealProof")"
seal_proof_version="$(extract_scoped_current_version "NuMetal-Q/NuSeal/SpartanProof.swift" "SealProof")"
metal_storage_layout_version="$(extract_scoped_current_version "NuMetal-Q/NuMetal/MetalABI.swift" "MetalStorageLayout")"

require_line "- \`MetalStorageLayout.currentVersion\` is now \`${metal_storage_layout_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`ShapePack.currentVersion\` is now \`${shape_pack_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`SealProof.currentVersion\` is now \`${seal_proof_version}\`." "METAL_FIRST_VNEXT.md"
require_line "- \`PublicSealProof.currentVersion\` is now \`${public_seal_proof_version}\`." "METAL_FIRST_VNEXT.md"

echo "Version metadata checks passed."
