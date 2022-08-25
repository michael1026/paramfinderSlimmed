package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
)

const letters = "abcdefghijklmnopqrstuvwxyz"

func RandSeq(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func ResponseToBodyString(resp *http.Response) (body string) {
	bodyString := ""

	for name, values := range resp.Header {
		for _, value := range values {
			bodyString += fmt.Sprintf("%s: %s", name, value)
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error getting string %s\n", err)
		return bodyString
	}
	bodyString = string(bodyBytes)

	return bodyString
}
