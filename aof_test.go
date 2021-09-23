package aof

import (
	"os"
	"reflect"
	"testing"
)

func TestAppendThenLookup(t *testing.T) {
	tmp, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	aof, err := NewAOF(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	if err = aof.Append([]byte("abcd")); err != nil {
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
		t.Errorf("%v != %v", off, 15)
	}
}

// TODO(AD)
