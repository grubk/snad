package snadbox

// Direction distinguishes which side of a transfer emitted an event.
type Direction string

const (
	DirectionSend Direction = "send"
	DirectionRecv Direction = "recv"
)

// TransferStarted is emitted once a file's header has been exchanged and
// its body is about to be streamed.
type TransferStarted struct {
	Peer      string
	File      string
	Size      int64
	Direction Direction
}

// TransferSkipped is emitted when a file was not transferred because the
// receiver already has a file by that name.
type TransferSkipped struct {
	Peer      string
	File      string
	Direction Direction
}

// TransferProgress is emitted periodically while a file's body streams.
type TransferProgress struct {
	Peer      string
	File      string
	Sent      int64
	Total     int64
	Direction Direction
}

// TransferDone is emitted once a file has been fully sent/received and its
// checksum verified.
type TransferDone struct {
	Peer      string
	File      string
	Direction Direction
}

// TransferError is emitted when a transfer fails for any reason (I/O error,
// checksum mismatch, handshake failure, peer fingerprint mismatch).
type TransferError struct {
	Peer      string
	File      string
	Direction Direction
	Err       error
}
