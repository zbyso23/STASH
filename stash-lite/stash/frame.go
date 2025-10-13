package stash

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "io"
    "os"
)

const Magic = "SF"

func WriteFrame(path string, w io.Writer, codecID byte) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer f.Close()

    fi, _ := f.Stat()
    uncompressedSize := uint64(fi.Size())

    // Write header (magic + version + codec)
    header := make([]byte, 2+1+1+8)
    copy(header[0:2], Magic)
    header[2] = 1       // version
    header[3] = codecID // codec id
    binary.LittleEndian.PutUint64(header[4:], uncompressedSize)
    w.Write(header)

    // Hash writer
    h := sha256.New()
    mw := io.MultiWriter(w, h)

    // Copy content
    if _, err := io.Copy(mw, f); err != nil {
        return "", err
    }

    // Final hash
    sum := h.Sum(nil)
    w.Write(sum)
    return fmt.Sprintf("%x", sum), nil
}
