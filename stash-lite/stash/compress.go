package stash

import (
    "compress/zlib"
    "compress/gzip"
    "io"
    "strings"
)

func CompressForExt(ext string, w io.Writer) (io.WriteCloser, string, error) {
    ext = strings.ToLower(ext)
    switch ext {
    case ".txt", ".json", ".html", ".js", ".css", ".xml":
        // simple text compressor
        zw := zlib.NewWriter(w)
        return zw, "zlib", nil
    default:
        // binary fallback (use gzip for simplicity)
        gw := gzip.NewWriter(w)
        return gw, "gzip", nil
    }
}
