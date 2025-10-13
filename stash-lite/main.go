package main

import (
	"fmt"
	"os"
	"path/filepath"
	"stashapp/stash"
)

// usage prints a short usage string to stderr.
func usage() {
	exe := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s pack|unpack <input_dir> <output_dir>\n", exe)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  pack   — create a STASH archive from files in <input_dir> and write frames and manifest.json into <output_dir>\n")
	fmt.Fprintf(os.Stderr, "  unpack — extract a STASH archive in <input_dir> to raw files in <output_dir> using manifest.json\n")
}

func main() {
	if len(os.Args) < 4 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	inputDir := os.Args[2]
	outputDir := os.Args[3]
	switch cmd {
	case "pack":
		if err := stash.CompressFolder(inputDir, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error during pack: %v\n", err)
			os.Exit(1)
		}
	case "unpack":
		if err := stash.DecompressFolder(inputDir, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error during unpack: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}
