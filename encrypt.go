package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
)

type MyStreamWriter struct {
	cipher.StreamWriter
}

func (w MyStreamWriter) Write(src []byte) (n int, err error) {
	c := src
	w.S.XORKeyStream(c, src)
	n, err = w.W.Write(c)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}
func encodeFile(key []byte, inPath, outPath string) error {
	slog.Info("Start EncryptFile", inPath, "to", "outPath", outPath)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	if keyLen := len(key); keyLen == 0 {
		key = iv
	} else if keyLen < 16 {
		key = append(key, iv[:16-keyLen]...)
	} else {
		key = key[:16]
	}
	slog.Info("EncryptFile", "Path", inPath, "key", key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	outPutFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer outPutFile.Close()
	if wlen, err := outPutFile.Write(iv); err != nil || wlen != aes.BlockSize {
		return fmt.Errorf("write iv failed, %w", err)
	}
	inPutFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inPutFile.Close()

	//writer := &cipher.StreamWriter{S: stream, W: outPutFile}
	writer := &MyStreamWriter{}
	writer.S = stream
	writer.W = outPutFile
	_, err = io.Copy(writer, inPutFile)
	if err != nil {
		return err
	}
	slog.Info("EncryptFile", "path", inPath, "outPath", outPath, "status", "success")
	return nil
}

func decodeFile(key []byte, inPath, outPath string) error {
	slog.Info("Start DecryptFile", inPath, "to", "outPath", outPath)
	inputFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(inputFile, iv); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: inputFile}
	outPutFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer outPutFile.Close()
	_, err = io.Copy(outPutFile, reader)
	if err != nil {
		return err
	}
	slog.Info("DecryptFile", "path", inPath, "outPath", outPath, "status", "success")
	return nil
}
