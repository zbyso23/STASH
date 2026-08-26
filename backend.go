package stash

import (
	"context"
	"io"
)

type Backend interface {
	Identity() string

	Blobs() BlobStore
	Metadata() MetadataStore
}

type BlobStore interface {
	OpenBlob(
		ctx context.Context,
		generation uint64,
		ordinal uint8,
	) (BlobReader, error)
}

type BlobReader interface {
	io.ReaderAt
	io.Closer

	Size(ctx context.Context) (int64, error)
}

type BlobWriterStore interface {
	BlobStore

	CreateBlob(
		ctx context.Context,
		generation uint64,
		ordinal uint8,
	) (BlobWriter, error)
}

type BlobWriter interface {
	io.ReaderAt
	io.WriterAt
	io.Closer

	Size(ctx context.Context) (int64, error)
	Sync(ctx context.Context) error
}

type MetadataStore interface {
	ReadRoot(ctx context.Context) (RootRef, error)

	ReadManifest(
		ctx context.Context,
		generation uint64,
	) (io.ReadCloser, error)

	ReadIndex(
		ctx context.Context,
		generation uint64,
		blob uint8,
	) (io.ReadCloser, error)
}

type MetadataWriterStore interface {
	MetadataStore

	WriteManifest(
		ctx context.Context,
		generation uint64,
	) (DurableWriter, error)

	WriteIndex(
		ctx context.Context,
		generation uint64,
		blob uint8,
	) (DurableWriter, error)

	PublishRoot(
		ctx context.Context,
		root RootRef,
	) error
}

type DurableWriter interface {
	io.Writer
	io.Closer

	Sync(ctx context.Context) error
}
