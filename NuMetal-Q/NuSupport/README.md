# NuSupport

Small internal helpers shared across serialization-heavy subsystems.

## Responsibilities

- little-endian fixed-width decoding
- binary writer/reader helpers for proof and envelope codecs

## Main Types

- `BinaryWriter`
- `BinaryReader`
- `LittleEndianCodec`

## Test Coverage

- direct coverage in `SupportCodecTests`
- indirect coverage through seal, envelope, sync, and vault tests
