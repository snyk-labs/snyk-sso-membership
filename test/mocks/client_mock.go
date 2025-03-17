package mocks

import (
	"bytes"
	"fmt"
	"io"

	"github.com/stretchr/testify/mock"
)

// MockSnykClient is a mock implementation of SnykClient for testing.
type MockSnykClient struct {
	mock.Mock
}

func (m *MockSnykClient) Get(uriPath string) ([]byte, error) {
	args := m.Called(uriPath)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSnykClient) Post(uriPath string, body io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, body)
	if err != nil {
		fmt.Println("mockclient err in reading body: " + err.Error())
		return nil, err
	}
	args := m.Called(uriPath, buf)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSnykClient) Patch(uriPath string, body io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, body)
	if err != nil {
		fmt.Println("mockclient err in reading body: " + err.Error())
		return nil, err
	}
	args := m.Called(uriPath, buf)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSnykClient) Delete(uriPath string) ([]byte, error) {
	args := m.Called(uriPath)
	return args.Get(0).([]byte), args.Error(1)
}
