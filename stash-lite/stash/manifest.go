package stash

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "time"
)

// FrameEntry records metadata about a frame in the manifest. Hash is the
// SHA-256 digest of the frame (excluding the trailing hash), encoded in hex.
// Codec is a human-readable string for the codec used in the frame.
// File stores the relative path to the frame file within the archive directory.
type FrameEntry struct {
    ID    uint64 `json:"id"`
    File  string `json:"file"`
    Hash  string `json:"hash"`
    Codec string `json:"codec"`
}

// ObjectManifestEntry describes a single object in the manifest. Frame is the
// ID of the frame that holds this object. Hash is the SHA-256 digest of the
// uncompressed object data (matching the value in the object table), encoded
// in hex. Size is the uncompressed size of the object.
type ObjectManifestEntry struct {
    Frame uint64 `json:"frame"`
    Hash  string `json:"hash"`
    Size  uint64 `json:"size"`
}

// Manifest represents the global index over all frames and objects in an
// archive. StashVersion identifies the specification version, Created records
// the ISO-8601 creation time, Frames lists frame metadata, and Objects maps
// object names to their definitions.
type Manifest struct {
    StashVersion int                             `json:"stash_version"`
    Created      string                          `json:"created"`
    Frames       []FrameEntry                    `json:"frames"`
    Objects      map[string]ObjectManifestEntry  `json:"objects"`
}

// NewManifest returns a manifest with default values filled in.
func NewManifest() *Manifest {
    return &Manifest{
        StashVersion: 1,
        Created:      time.Now().UTC().Format(time.RFC3339),
        Frames:       []FrameEntry{},
        Objects:      make(map[string]ObjectManifestEntry),
    }
}

// Save writes the manifest to the given file path with pretty JSON formatting.
func (m *Manifest) Save(filePath string) error {
    data, err := json.MarshalIndent(m, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal manifest: %w", err)
    }
    return os.WriteFile(filePath, data, 0644)
}

// LoadManifest reads and parses a manifest from a JSON file at the given path.
func LoadManifest(filePath string) (*Manifest, error) {
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, err
    }
    var m Manifest
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, fmt.Errorf("failed to parse manifest: %w", err)
    }
    return &m, nil
}