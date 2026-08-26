type Archive interface {
	Generation() GenerationID

	Begin(ctx context.Context) (Transaction, error)

	OpenObject(
		ctx context.Context,
		path string,
		opts OpenObjectOptions,
	) (ObjectReader, error)

	List(
		ctx context.Context,
		prefix string,
		opts ListOptions,
	) (ObjectIterator, error)

	Stat(
		ctx context.Context,
		path string,
	) (ObjectInfo, error)

	Verify(
		ctx context.Context,
		opts VerifyOptions,
	) (VerifyReport, error)

	Recover(
		ctx context.Context,
		opts RecoverOptions,
	) (RecoveryReport, error)

	RebuildIndexes(
		ctx context.Context,
		opts IndexOptions,
	) error

	Compact(
		ctx context.Context,
		opts CompactOptions,
	) (CompactReport, error)

	Close() error
}

type Transaction interface {
	Put(
		ctx context.Context,
		path string,
		src io.Reader,
		opts PutOptions,
	) error

	Delete(
		ctx context.Context,
		path string,
	) error

	Rename(
		ctx context.Context,
		oldPath string,
		newPath string,
	) error

	Commit(ctx context.Context) error

	Abort(ctx context.Context) error
}

var ErrTransactionClosed = errors.New(
	"stash: transaction already completed",
)

type ObjectReader interface {
	io.Reader
	io.ReaderAt
	io.Closer
}

type ObjectIterator interface {
	Next(ctx context.Context) bool
	Object() ObjectInfo
	Err() error
	Close() error
}

type ObjectInfo struct {
	Path string

	Version  uint64
	ObjectID ObjectID

	Size uint64

	ExtentCount uint64
}

type ExtentInfo struct {
	Hash FrameHash

	Blob BlobOrdinal

	LogicalOffset uint64
	LogicalLength uint64
}

StatOptions{
	IncludeExtents: true,
}

type VerifyReport struct {
	Generation GenerationID

	BlobsChecked   uint64
	FramesChecked  uint64
	ObjectsChecked uint64

	BytesChecked uint64

	Issues []VerifyIssue
}

type VerifyReport struct {
	Generation GenerationID

	BlobsChecked   uint64
	FramesChecked  uint64
	ObjectsChecked uint64

	BytesChecked uint64

	Issues []VerifyIssue
}

type VerifySeverity uint8

const (
	VerifyInfo VerifySeverity = iota
	VerifyWarning
	VerifyError
)

type VerifyIssue struct {
	Severity VerifySeverity
	Code     IntegrityCode

	Generation *GenerationID
	Blob       *BlobOrdinal
	Offset     *uint64

	Path     string
	ObjectID *ObjectID

	Message string
}

type VerifyOptions struct {
	Full bool

	Progress ProgressFunc
	OnIssue  func(VerifyIssue) error
}
type VerifyReport struct {
	FramesChecked uint64
	Errors        uint64
	Warnings      uint64
}

type Progress struct {
	Phase string

	BlobsDone  uint64
	FramesDone uint64
	BytesDone  uint64
}

type ProgressFunc func(Progress) error