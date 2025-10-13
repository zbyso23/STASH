package stash

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// CompressFolder walks through the input directory, creates a separate STASH
// frame for every file encountered, and writes both the frames and a
// manifest.json into the output directory. The output directory will be
// created if it does not already exist. The codec used for compression is
// gzip (CodecGzip).
func CompressFolder(inputDir, outputDir string) error {
	// Ensure input directory exists
	stat, err := os.Stat(inputDir)
	if err != nil {
		return fmt.Errorf("input directory error: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("input path is not a directory: %s", inputDir)
	}
	// Create output directory if necessary
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	// Initialize manifest
	manifest := NewManifest()
	var frameID uint64 = 1
	// Walk inputDir recursively
	err = filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		// Compute relative path
		rel, err := filepath.Rel(inputDir, path)
		if err != nil {
			return err
		}
		// Read file contents
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}
		// Create frame bytes using gzip
		fi, err := d.Info()
		if err != nil {
			return err
		}
		frameBytes, frameHash, err := CreateFrame(frameID, CodecGzip, data, filepath.ToSlash(rel), fi.ModTime().Unix())
		if err != nil {
			return fmt.Errorf("failed to create frame for %s: %w", path, err)
		}
		// Compute object hash again (matches object table). We compute from data for manifest.
		objHashHex := HashSHA256Hex(data)
		// Write frame file
		frameFileName := fmt.Sprintf("frame_%d.stash", frameID)
		frameFilePath := filepath.Join(outputDir, frameFileName)
		if err := os.WriteFile(frameFilePath, frameBytes, 0644); err != nil {
			return fmt.Errorf("failed to write frame file %s: %w", frameFileName, err)
		}
		// Append entry to manifest.Frames
		manifest.Frames = append(manifest.Frames, FrameEntry{
			ID:    frameID,
			File:  frameFileName,
			Hash:  frameHash,
			Codec: "gzip",
		})
		// Add object entry to manifest.Objects
		manifest.Objects[filepath.ToSlash(rel)] = ObjectManifestEntry{
			Frame: frameID,
			Hash:  objHashHex,
			Size:  uint64(len(data)),
		}
		frameID++
		return nil
	})
	if err != nil {
		return err
	}
	// Write manifest to outputDir/manifest.json
	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := manifest.Save(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}
	return nil
}
