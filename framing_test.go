package ktls

import (
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nopConn provides net.Conn stubs for test connections.
type nopConn struct{}

func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }

// boundaryConn serves a fixed byte stream and, in strict mode, fails the test
// when a read request could pull bytes across the next record sub-boundary
// (end of a record header or end of a record body) out of the "kernel".
type boundaryConn struct {
	nopConn

	t          *testing.T
	data       []byte
	pos        int
	boundaries []int
	rnd        *rand.Rand
	strict     bool
}

func (b *boundaryConn) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}

	if b.strict {
		next := len(b.data)
		for _, bd := range b.boundaries {
			if bd > b.pos {
				next = bd

				break
			}
		}
		require.LessOrEqual(b.t, len(p), next-b.pos, "read request crosses record boundary at pos %d", b.pos)
	}

	n := len(p)
	if b.rnd != nil && n > 1 {
		n = 1 + b.rnd.IntN(n)
	}
	n = min(n, len(b.data)-b.pos)
	copy(p, b.data[b.pos:b.pos+n])
	b.pos += n

	return n, nil
}

// record builds a TLS record with the given content type and body length.
func record(typ byte, bodyLen int) []byte {
	r := make([]byte, recordHeaderLen+bodyLen)
	r[0] = typ
	r[1], r[2] = 3, 3
	r[3] = byte(bodyLen >> 8)
	r[4] = byte(bodyLen)
	for i := range bodyLen {
		r[recordHeaderLen+i] = byte(i)
	}

	return r
}

// stream concatenates records and returns the sub-boundary offsets.
func stream(recs ...[]byte) (data []byte, boundaries []int) {
	off := 0
	for _, r := range recs {
		data = append(data, r...)
		boundaries = append(boundaries, off+recordHeaderLen, off+len(r))
		off += len(r)
	}

	return data, boundaries
}

func readAll(t *testing.T, f *framedConn, bufSize int) int {
	t.Helper()

	total := 0
	buf := make([]byte, bufSize)

	for {
		n, err := f.Read(buf)
		total += n
		if err == io.EOF {
			return total
		}
		require.NoError(t, err)
	}
}

func TestFramerNeverReadsAcrossBoundaries(t *testing.T) {
	recs := [][]byte{
		record(recordTypeHandshake, 517),      // ClientHello
		record(20, 1),                         // ChangeCipherSpec
		record(recordTypeApplicationData, 53), // client Finished (disguised)
		record(recordTypeApplicationData, 16384),
	}
	data, bounds := stream(recs...)

	for _, bufSize := range []int{1, 4, recordHeaderLen, 333, 16384, 65536} {
		for seed := range uint64(3) {
			var rnd *rand.Rand
			if seed > 0 {
				rnd = rand.New(rand.NewPCG(seed, 42))
			}

			f := &framedConn{Conn: &boundaryConn{t: t, data: data, boundaries: bounds, strict: true, rnd: rnd}}
			total := readAll(t, f, bufSize)

			assert.Equal(t, len(data), total, "bufSize %d seed %d", bufSize, seed)
			assert.Equal(t, 2, f.rxApp, "bufSize %d seed %d", bufSize, seed)
			assert.True(t, f.readAtBoundary(), "bufSize %d seed %d", bufSize, seed)
		}
	}
}

func TestFramerStopsMidRecord(t *testing.T) {
	full := record(recordTypeApplicationData, 100)
	data, bounds := stream(full)
	truncated := data[:recordHeaderLen+40] // body cut short

	f := &framedConn{Conn: &boundaryConn{t: t, data: truncated, boundaries: bounds, strict: true}}
	readAll(t, f, 4096)

	assert.False(t, f.readAtBoundary())
	assert.Equal(t, 0, f.rxApp, "incomplete record must not be counted")
}

func TestFramerZeroLengthRecord(t *testing.T) {
	data, bounds := stream(record(recordTypeApplicationData, 0), record(recordTypeHandshake, 5))

	f := &framedConn{Conn: &boundaryConn{t: t, data: data, boundaries: bounds, strict: true}}
	readAll(t, f, 4096)

	assert.Equal(t, 1, f.rxApp)
	assert.True(t, f.readAtBoundary())
}

func TestFramerReleasePassthrough(t *testing.T) {
	data, _ := stream(record(recordTypeHandshake, 10), record(recordTypeApplicationData, 10))

	f := &framedConn{Conn: &boundaryConn{t: t, data: data, strict: false}}
	f.release()

	n, err := f.Read(make([]byte, len(data)))
	require.NoError(t, err)
	assert.Equal(t, len(data), n, "released framer must not cap reads")
	assert.Equal(t, 0, f.rxApp, "released framer must not track records")
}

func TestFramerWriteCapturesLastAppRecord(t *testing.T) {
	f := &framedConn{Conn: nopConn{}}

	write := func(b []byte) {
		t.Helper()
		n, err := f.Write(b)
		require.NoError(t, err)
		require.Equal(t, len(b), n)
	}

	first := record(recordTypeApplicationData, 40)
	write(first)
	assert.Equal(t, first, f.wLast)

	// Non-application-data records must not disturb the captured record.
	write(record(recordTypeHandshake, 10))
	assert.Equal(t, first, f.wLast)

	// A record written in odd chunks is captured whole.
	ticket := record(recordTypeApplicationData, 245)
	for off := 0; off < len(ticket); off += 7 {
		write(ticket[off:min(off+7, len(ticket))])
	}
	assert.Equal(t, ticket, f.wLast)

	// Multiple records in a single write: the last one wins, even zero-length.
	var batch []byte
	batch = append(batch, record(recordTypeApplicationData, 5)...)
	batch = append(batch, record(recordTypeAlert, 2)...)
	batch = append(batch, record(recordTypeApplicationData, 0)...)
	write(batch)
	assert.Equal(t, record(recordTypeApplicationData, 0), f.wLast)
}

func TestFramerWriteCaptureReleased(t *testing.T) {
	f := &framedConn{Conn: nopConn{}}
	f.release()

	_, err := f.Write(record(recordTypeApplicationData, 10))
	require.NoError(t, err)
	assert.Nil(t, f.wLast)
}
