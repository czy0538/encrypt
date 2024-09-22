package encrypt

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"io"
	"log/slog"
	"os"
	"testing"
)

const chunkSize = 1024 * 1024 // 每次读取1MB

func compareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func compareFiles(file1, file2 string) (bool, error) {
	f1, err := os.Open(file1)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	for {
		n1, err1 := f1.Read(buf1)
		n2, err2 := f2.Read(buf2)

		if err1 != nil && err1 != io.EOF {
			return false, err1
		}
		if err2 != nil && err2 != io.EOF {
			return false, err2
		}

		if n1 != n2 || !compareByteSlices(buf1[:n1], buf2[:n2]) {
			return false, nil
		}

		if err1 == io.EOF && err2 == io.EOF {
			break
		}
	}
	return true, nil
}

func TestEncryptDecryptFile(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.Info("TestEncryptDecryptFile")
	inFile, err := os.CreateTemp("", "test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inFile.Name())
	//_, err = io.Copy(inFile, strings.NewReader("hello,world"))
	_, err = io.CopyN(inFile, rand.Reader, 1024*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	inPath := inFile.Name()
	outFile, err := os.CreateTemp("", "test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outFile.Name())
	outPath := outFile.Name()
	key := []byte("abcedfghijklmnop")
	err = encodeFile(key, inPath, outPath)
	if err != nil {
		t.Fatal(err)
	}
	err = outFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp("", "test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = decodeFile(key, outPath, file.Name())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := compareFiles(inPath, file.Name())
	assert.True(t, ok)
	assert.NoError(t, err)
}
