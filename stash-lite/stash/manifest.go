package stash

import (
    "encoding/json"
    "os"
    "time"
)

type FrameInfo struct {
    File  string `json:"file"`
    Codec string `json:"codec"`
    Hash  string `json:"hash"`
}

type Manifest struct {
    Version  int          `json:"stash_version"`
    Created  string       `json:"created"`
    Frames   []FrameInfo  `json:"frames"`
}

func WriteManifest(frames []FrameInfo, outPath string) error {
    manifest := Manifest{
        Version: 1,
        Created: time.Now().UTC().Format(time.RFC3339),
        Frames:  frames,
    }
    f, err := os.Create(outPath)
    if err != nil {
        return err
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    return enc.Encode(manifest)
}
