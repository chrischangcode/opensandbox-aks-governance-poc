package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// PolicyRevision hashes a canonical JSON representation shared with the harness.
func PolicyRevision(spec map[string]any) (string, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(spec); err != nil {
		return "", err
	}
	canonical := bytes.TrimSuffix(body.Bytes(), []byte{'\n'})
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
