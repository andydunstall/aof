package aof

import (
	"io"
	"os"
	"reflect"
	"testing"
)

func TestAppendThenLookup(t *testing.T) {
	aof, _ := tempAOF(t)

	if err := aof.Append([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	b, off, err := aof.Lookup(0)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte("abcd"), b) {
		t.Errorf("%v != %v", []byte("abcd"), b)
	}
	if off != 14 {
		t.Errorf("%v != %v", off, 14)
	}
}

func TestAppendThenLookupInvalidChunkFindsNext(t *testing.T) {
	aof, path := tempAOF(t)

	if err := aof.Append([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if err := aof.Append([]byte("efgh")); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, perm)
	if err != nil {
		t.Fatal(err)
	}
	// Set first byte of CRC to 0.
	f.Seek(10, 0)
	f.Write([]byte{0})

	b, off, err := aof.Lookup(0)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte("efgh"), b) {
		t.Errorf("%v != %v", []byte("efgh"), b)
	}
	if off != 28 {
		t.Errorf("%v != %v", off, 28)
	}
}

func TestAppendThenLookupInvalidChunkFindsNextIncludesCookie(t *testing.T) {
	aof, path := tempAOF(t)

	if err := aof.Append([]byte{0x24, 0x71, 0x62, 0x69}); err != nil {
		t.Fatal(err)
	}
	if err := aof.Append([]byte{0x24, 0x71, 0x62, 0x69}); err != nil {
		t.Fatal(err)
	}
	if err := aof.Append([]byte{0x24, 0x71, 0x62, 0x69}); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, perm)
	if err != nil {
		t.Fatal(err)
	}
	// Set first byte of CRC to 0.
	f.Seek(10, 0)
	f.Write([]byte{0})

	b, off, err := aof.Lookup(0)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte{0x24, 0x71, 0x62, 0x69}, b) {
		t.Errorf("%v != %v", []byte{0x24, 0x71, 0x62, 0x69}, b)
	}
	if off != 28 {
		t.Errorf("%v != %v", off, 28)
	}

	b, off, err = aof.Lookup(off)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte{0x24, 0x71, 0x62, 0x69}, b) {
		t.Errorf("%v != %v", []byte{0x24, 0x71, 0x62, 0x69}, b)
	}
	if off != 42 {
		t.Errorf("%v != %v", off, 28)
	}
}

func TestAppendPartialWriteIgnored(t *testing.T) {
	aof, path := tempAOF(t)

	if err := aof.Append([]byte{0x24, 0x71, 0x62, 0x69}); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, perm)
	if err != nil {
		t.Fatal(err)
	}
	f.Seek(0, 0)
	// Remove half of the write.
	f.Truncate(7)

	if err := aof.Append([]byte{0x24, 0x71, 0x62, 0x69}); err != nil {
		t.Fatal(err)
	}

	b, off, err := aof.Lookup(0)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte{0x24, 0x71, 0x62, 0x69}, b) {
		t.Errorf("%v != %v", []byte{0x24, 0x71, 0x62, 0x69}, b)
	}
	if off != 21 {
		t.Errorf("%v != %v", off, 28)
	}
}

func TestAppendThenLookupInvalidCRC(t *testing.T) {
	aof, path := tempAOF(t)

	if err := aof.Append([]byte("abcd")); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, perm)
	if err != nil {
		t.Fatal(err)
	}
	// Set first byte of CRC to 0.
	f.Seek(10, 0)
	f.Write([]byte{0})

	_, _, err = aof.Lookup(0)
	if err != io.EOF {
		t.Errorf("%v != %v", err, io.EOF)
	}
}

func TestAppendTooLarge(t *testing.T) {
	aof, _ := tempAOF(t)

	if err := aof.Append(make([]byte, 1025)); err != ErrChunkSizeLimitExceeded {
		t.Errorf("%v != %v", err, ErrChunkSizeLimitExceeded)
	}
}

func tempAOF(t *testing.T) (*AOF, string) {
	tmp, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	aof, err := NewAOF(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return aof, tmp.Name()
}
