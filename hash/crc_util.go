package hash

import (
	"encoding/base64"
	"encoding/hex"
	"hash/crc32"

	cryptolib "cryptolib"
)

// ==== CRC Operations ===== //
// ==== CRC Operations ===== //

// CRC32Encode CRC32Encode
func CRC32Encode(data string) uint32 {
	return crc32.ChecksumIEEE([]byte(data))
}

// CRC32Hex CRC32Hex
func CRC32Hex(data string) string {
	cipherStr := CRC32Encode(data)
	hjx := cryptolib.ParseUint32ToBytes(cipherStr)

	return hex.EncodeToString(hjx)
}

// CRC32Base64 CRC32Base64
func CRC32Base64(data string) string {
	cipherStr := CRC32Encode(data)
	hjx := cryptolib.ParseUint32ToBytes(cipherStr)

	return base64.StdEncoding.EncodeToString(hjx)
}
