// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"log/slog"
)

// FileMode is the operational mode of a file command.
type FileMode uint16

// File modes.
const (
	FileModeNull   FileMode = 0
	FileModeRead   FileMode = 1
	FileModeWrite  FileMode = 2
	FileModeAppend FileMode = 3
)

// String returns "NULL", "READ", "WRITE", "APPEND" or "MODE(n)".
func (m FileMode) String() string {
	switch m {
	case FileModeNull:
		return "NULL"
	case FileModeRead:
		return "READ"
	case FileModeWrite:
		return "WRITE"
	case FileModeAppend:
		return "APPEND"
	default:
		return fmt.Sprintf("MODE(%d)", uint16(m))
	}
}

// FileStatus is the status code of a file command or transport status.
type FileStatus uint8

// File status codes (IEEE 1815-2012 Table 11-32).
const (
	FileSuccess          FileStatus = 0
	FilePermissionDenied FileStatus = 1
	FileInvalidMode      FileStatus = 2
	FileNotFound         FileStatus = 3
	FileLocked           FileStatus = 4
	FileTooManyOpen      FileStatus = 5
	FileInvalidHandle    FileStatus = 6
	FileWriteBlockSize   FileStatus = 7
	FileCommLost         FileStatus = 8
	FileCannotAbort      FileStatus = 9
	FileNotOpened        FileStatus = 16
	FileHandleExpired    FileStatus = 17
	FileBufferOverrun    FileStatus = 18
	FileFatal            FileStatus = 19
	FileBlockSequence    FileStatus = 20
	FileUndefined        FileStatus = 255
)

var fileStatusNames = map[FileStatus]string{
	FileSuccess: "SUCCESS", FilePermissionDenied: "PERMISSION_DENIED", FileInvalidMode: "INVALID_MODE",
	FileNotFound: "FILE_NOT_FOUND", FileLocked: "FILE_LOCKED", FileTooManyOpen: "TOO_MANY_OPEN",
	FileInvalidHandle: "INVALID_HANDLE", FileWriteBlockSize: "WRITE_BLOCK_SIZE", FileCommLost: "COMM_LOST",
	FileCannotAbort: "CANNOT_ABORT", FileNotOpened: "NOT_OPENED", FileHandleExpired: "HANDLE_EXPIRED",
	FileBufferOverrun: "BUFFER_OVERRUN", FileFatal: "FATAL", FileBlockSequence: "BLOCK_SEQ",
	FileUndefined: "UNDEFINED",
}

// String returns the name of the status, for example "FILE_NOT_FOUND".
func (s FileStatus) String() string {
	if n, ok := fileStatusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("FILE_STATUS(%d)", uint8(s))
}

// FileType is the type in a file descriptor.
type FileType uint16

// File types.
const (
	FileTypeDirectory FileType = 0
	FileTypeSimple    FileType = 1
)

// Permissions are the Unix-style permission bits of a file: read, write
// and execute for owner, group and world.
type Permissions uint16

// Permission bits.
const (
	PermWorldExecute Permissions = 1 << iota
	PermWorldWrite
	PermWorldRead
	PermGroupExecute
	PermGroupWrite
	PermGroupRead
	PermOwnerExecute
	PermOwnerWrite
	PermOwnerRead
)

// String returns the permissions as "rwxr-x---".
func (p Permissions) String() string {
	const rwx = "rwxrwxrwx"
	b := []byte("---------")
	for i := range 9 {
		if p&(1<<(8-i)) != 0 {
			b[i] = rwx[i]
		}
	}
	return string(b)
}

// FileAuthentication is a file authentication object (g70v2): the
// credentials sent with AUTHENTICATE_FILE, and the key returned.
type FileAuthentication struct {
	UserName, Password string
	AuthKey            uint32
}

// String formats the object without its password and key, so that
// printing a decoded request does not reveal them.
func (v FileAuthentication) String() string {
	return fmt.Sprintf("{UserName:%q Password:%s AuthKey:%s}", v.UserName, redact(v.Password != ""), redact(v.AuthKey != 0))
}

// GoString is String, for %#v.
func (v FileAuthentication) GoString() string { return "app.FileAuthentication" + v.String() }

// LogValue logs the user name only, for log/slog.
func (v FileAuthentication) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", v.UserName),
		slog.String("password", redact(v.Password != "")), slog.String("auth_key", redact(v.AuthKey != 0)))
}

// redact stands for a secret in formatted output.
func redact(set bool) string {
	if set {
		return "[REDACTED]"
	}
	return "[none]"
}

// FileCommand is a file command object (g70v3), sent with OPEN_FILE and
// DELETE_FILE.
type FileCommand struct {
	Name        string
	Created     Timestamp
	Permissions Permissions
	AuthKey     uint32
	// Size is the size of the file to write, or 0.
	Size         uint32
	Mode         FileMode
	MaxBlockSize uint16
	RequestID    uint16
}

// FileCommandStatus is a file command status object (g70v4), the answer
// to OPEN_FILE, CLOSE_FILE, DELETE_FILE and ABORT_FILE.
type FileCommandStatus struct {
	Handle       uint32
	Size         uint32
	MaxBlockSize uint16
	RequestID    uint16
	Status       FileStatus
	// Text is optional additional information.
	Text string
}

// FileTransport is a file transport object (g70v5): one block of file
// data.
type FileTransport struct {
	Handle uint32
	// Block is the block number, 0..0x7FFFFFFF.
	Block uint32
	// Last marks the last block of the file (the top bit of the block
	// number on the wire).
	Last bool
	Data []byte
}

// FileTransportStatus is a file transport status object (g70v6): the
// acknowledgement of a written block.
type FileTransportStatus struct {
	Handle uint32
	Block  uint32
	Last   bool
	Status FileStatus
	Text   string
}

// FileDescriptor is a file descriptor object (g70v7): one entry of a
// directory, or the answer to GET_FILE_INFO.
type FileDescriptor struct {
	Name        string
	Type        FileType
	Size        uint32
	Created     Timestamp
	Permissions Permissions
	RequestID   uint16
}

// FileSpecification is a file specification string (g70v8), used by
// ACTIVATE_CONFIG.
type FileSpecification struct {
	Name string
}

func (FileAuthentication) isValue()  {}
func (FileCommand) isValue()         {}
func (FileCommandStatus) isValue()   {}
func (FileTransport) isValue()       {}
func (FileTransportStatus) isValue() {}
func (FileDescriptor) isValue()      {}
func (FileSpecification) isValue()   {}

// Fixed offsets of the strings in the file objects: everything before
// them has a fixed size.
const (
	g70v2NameOffset = 12
	g70v3NameOffset = 26
	g70v7NameOffset = 20
	lastBlockBit    = 0x80000000
)

func decFileAuth(b []byte) (Value, error) {
	r := reader{b: b}
	uo, us, po, ps, key := r.u16(), r.u16(), r.u16(), r.u16(), r.u32()
	if r.err != nil || uo != g70v2NameOffset || po != uo+us {
		return nil, malformed("g70v2 string offsets %d/%d", uo, po)
	}
	u, p := r.bytes(int(us)), r.bytes(int(ps))
	if err := r.done(); err != nil {
		return nil, err
	}
	return FileAuthentication{UserName: string(u), Password: string(p), AuthKey: key}, nil
}

func encFileAuth(b []byte, v FileAuthentication) ([]byte, error) {
	if len(v.UserName)+len(v.Password) > 0xFFFF-g70v2NameOffset {
		return b, invalid("g70v2 strings too long")
	}
	b = le16(b, g70v2NameOffset)
	b = le16(b, uint16(len(v.UserName)))
	b = le16(b, uint16(g70v2NameOffset+len(v.UserName)))
	b = le16(b, uint16(len(v.Password)))
	b = le32(b, v.AuthKey)
	b = append(b, v.UserName...)
	return append(b, v.Password...), nil
}

func decFileCommand(b []byte) (Value, error) {
	r := reader{b: b}
	off, n := r.u16(), r.u16()
	v := FileCommand{Created: r.time(), Permissions: Permissions(r.u16()), AuthKey: r.u32(), Size: r.u32(),
		Mode: FileMode(r.u16()), MaxBlockSize: r.u16(), RequestID: r.u16()}
	if r.err == nil && off != g70v3NameOffset {
		return nil, malformed("g70v3 name offset %d", off)
	}
	v.Name = string(r.bytes(int(n)))
	return v, r.done()
}

func encFileCommand(b []byte, v FileCommand) ([]byte, error) {
	if len(v.Name) > 0xFFFF {
		return b, invalid("g70v3 name too long")
	}
	b = le16(b, g70v3NameOffset)
	b = le16(b, uint16(len(v.Name)))
	b = le48(b, v.Created)
	b = le16(b, uint16(v.Permissions))
	b = le32(b, v.AuthKey)
	b = le32(b, v.Size)
	b = le16(b, uint16(v.Mode))
	b = le16(b, v.MaxBlockSize)
	b = le16(b, v.RequestID)
	return append(b, v.Name...), nil
}

func decFileCommandStatus(b []byte) (Value, error) {
	r := reader{b: b}
	v := FileCommandStatus{Handle: r.u32(), Size: r.u32(), MaxBlockSize: r.u16(), RequestID: r.u16(), Status: FileStatus(r.u8())}
	v.Text = string(r.rest())
	return v, r.done()
}

func encFileCommandStatus(b []byte, v FileCommandStatus) []byte {
	b = le32(b, v.Handle)
	b = le32(b, v.Size)
	b = le16(b, v.MaxBlockSize)
	b = le16(b, v.RequestID)
	b = append(b, byte(v.Status))
	return append(b, v.Text...)
}

func decFileTransport(b []byte) (Value, error) {
	r := reader{b: b}
	v := FileTransport{Handle: r.u32()}
	blk := r.u32()
	v.Block, v.Last = blk&^lastBlockBit, blk&lastBlockBit != 0
	v.Data = clone(r.rest())
	return v, r.done()
}

func encFileTransport(b []byte, v FileTransport) ([]byte, error) {
	if v.Block&lastBlockBit != 0 {
		return b, invalid("g70v5 block number %d", v.Block)
	}
	b = le32(b, v.Handle)
	b = le32(b, blockNumber(v.Block, v.Last))
	return append(b, v.Data...), nil
}

func decFileTransportStatus(b []byte) (Value, error) {
	r := reader{b: b}
	v := FileTransportStatus{Handle: r.u32()}
	blk := r.u32()
	v.Block, v.Last = blk&^lastBlockBit, blk&lastBlockBit != 0
	v.Status = FileStatus(r.u8())
	v.Text = string(r.rest())
	return v, r.done()
}

func encFileTransportStatus(b []byte, v FileTransportStatus) ([]byte, error) {
	if v.Block&lastBlockBit != 0 {
		return b, invalid("g70v6 block number %d", v.Block)
	}
	b = le32(b, v.Handle)
	b = le32(b, blockNumber(v.Block, v.Last))
	b = append(b, byte(v.Status))
	return append(b, v.Text...), nil
}

func blockNumber(n uint32, last bool) uint32 {
	if last {
		return n | lastBlockBit
	}
	return n
}

func decFileDescriptor(b []byte) (Value, error) {
	r := reader{b: b}
	off, n := r.u16(), r.u16()
	v := FileDescriptor{Type: FileType(r.u16()), Size: r.u32(), Created: r.time(), Permissions: Permissions(r.u16()), RequestID: r.u16()}
	if r.err == nil && off != g70v7NameOffset {
		return nil, malformed("g70v7 name offset %d", off)
	}
	v.Name = string(r.bytes(int(n)))
	return v, r.done()
}

func encFileDescriptor(b []byte, v FileDescriptor) ([]byte, error) {
	if len(v.Name) > 0xFFFF {
		return b, invalid("g70v7 name too long")
	}
	b = le16(b, g70v7NameOffset)
	b = le16(b, uint16(len(v.Name)))
	b = le16(b, uint16(v.Type))
	b = le32(b, v.Size)
	b = le48(b, v.Created)
	b = le16(b, uint16(v.Permissions))
	b = le16(b, v.RequestID)
	return append(b, v.Name...), nil
}

// AppendFileDescriptor appends the encoding of one file descriptor
// object (without object header), the form in which a directory's
// entries are transferred as the content of the directory file.
func AppendFileDescriptor(b []byte, d FileDescriptor) ([]byte, error) {
	return encFileDescriptor(b, d)
}

// DecodeFileDescriptors decodes the content of a directory file: a
// sequence of file descriptor objects.
func DecodeFileDescriptors(b []byte) ([]FileDescriptor, error) {
	var out []FileDescriptor
	for len(b) > 0 {
		if len(b) < g70v7NameOffset {
			return out, truncated("file descriptor: %d octets", len(b))
		}
		n := g70v7NameOffset + int(uint16(b[2])|uint16(b[3])<<8)
		if len(b) < n {
			return out, truncated("file descriptor name")
		}
		v, err := decFileDescriptor(b[:n])
		if err != nil {
			return out, err
		}
		out = append(out, v.(FileDescriptor))
		b = b[n:]
	}
	return out, nil
}
