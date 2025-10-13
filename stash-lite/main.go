package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "stash-lite/stash"
)

func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: stash-lite pack <folder>")
        os.Exit(1)
    }

    cmd := os.Args[1]
    target := os.Args[2]

    if cmd == "pack" {
        packFolder(target)
    } else {
        fmt.Println("Unknown command")
    }
}

func packFolder(root string) {
    out, _ := os.Create("archive.stash")
    defer out.Close()

    var frames []stash.FrameInfo

    filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if info.IsDir() { return nil }

        ext := strings.ToLower(filepath.Ext(path))
        zw, codec, _ := stash.CompressForExt(ext, out)
        hash, _ := stash.WriteFrame(path, zw, 1)
        zw.Close()

        frames = append(frames, stash.FrameInfo{
            File: path,
            Codec: codec,
            Hash: hash,
        })
        fmt.Println("Packed:", path)
        return nil
    })

    stash.WriteManifest(frames, "manifest.json")
}
