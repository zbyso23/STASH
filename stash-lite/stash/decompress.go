package stash

import (
    "fmt"
    "os"
    "path/filepath"
)

// DecompressFolder reads the manifest.json from the input directory and
// reconstructs the original files into the output directory. It verifies the
// integrity of frames and objects against the recorded hashes. Any mismatch
// will result in an error and abort the operation.
func DecompressFolder(inputDir, outputDir string) error {
    // Ensure manifest exists
    manifestPath := filepath.Join(inputDir, "manifest.json")
    manifest, err := LoadManifest(manifestPath)
    if err != nil {
        return fmt.Errorf("failed to load manifest: %w", err)
    }
    // Build map of frame ID to frame entry for quick lookup
    frameMap := make(map[uint64]FrameEntry, len(manifest.Frames))
    for _, f := range manifest.Frames {
        frameMap[f.ID] = f
    }
    // Group objects by frame
    frameObjects := make(map[uint64][]string)
    for name, obj := range manifest.Objects {
        frameObjects[obj.Frame] = append(frameObjects[obj.Frame], name)
    }
    // Create outputDir if needed
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        return fmt.Errorf("failed to create output directory: %w", err)
    }
    // Process each frame
    for frameID, objNames := range frameObjects {
        fEntry, ok := frameMap[frameID]
        if !ok {
            return fmt.Errorf("frame ID %d referenced by objects but not found in manifest", frameID)
        }
        framePath := filepath.Join(inputDir, fEntry.File)
        frameBytes, err := os.ReadFile(framePath)
        if err != nil {
            return fmt.Errorf("failed to read frame %s: %w", fEntry.File, err)
        }
        // Decode frame and verify hash
        fm, err := ParseFrame(frameBytes)
        if err != nil {
            return fmt.Errorf("failed to parse frame %d: %w", frameID, err)
        }
        // Verify manifest hash matches computed frame hash
        if fEntry.Hash != fm.Hash {
            return fmt.Errorf("frame %d hash mismatch: manifest %s vs computed %s", frameID, fEntry.Hash, fm.Hash)
        }
        // For each object in this frame, extract the slice
        for _, objName := range objNames {
            objManifest := manifest.Objects[objName]
            // Locate object within frame metadata
            var fo *FrameObject
            for i := range fm.Objects {
                if fm.Objects[i].Name == objName {
                    fo = &fm.Objects[i]
                    break
                }
            }
            if fo == nil {
                return fmt.Errorf("object %s not found in frame %d", objName, frameID)
            }
            // Ensure offsets are within bounds
            end := fo.Offset + fo.Size
            if end > uint64(len(fm.Data)) {
                return fmt.Errorf("object %s out of bounds in frame %d", objName, frameID)
            }
            objData := fm.Data[fo.Offset:end]
            // Verify object hash matches manifest
            objHashHex := HashSHA256Hex(objData)
            if objHashHex != objManifest.Hash {
                return fmt.Errorf("object %s hash mismatch: manifest %s vs computed %s", objName, objManifest.Hash, objHashHex)
            }
            // Compute destination path and ensure directories exist
            destPath := filepath.Join(outputDir, filepath.FromSlash(objName))
            if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
                return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(destPath), err)
            }
            // Write file
            if err := os.WriteFile(destPath, objData, 0644); err != nil {
                return fmt.Errorf("failed to write file %s: %w", destPath, err)
            }
        }
    }
    return nil
}