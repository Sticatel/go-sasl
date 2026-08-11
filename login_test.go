package sasl_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Sticatel/go-sasl"
)

func TestNewLoginClient(t *testing.T) {
	c := sasl.NewLoginClient("username", "Password:")

	mech, resp, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "LOGIN" {
		t.Error("Invalid mechanism name:", mech)
	}

	expected := []byte{117, 115, 101, 114, 110, 97, 109, 101}
	if bytes.Compare(resp, expected) != 0 {
		t.Error("Invalid initial response:", resp)
	}

	resp, err = c.Next(expected)
	if err != sasl.ErrUnexpectedServerChallenge {
		t.Error("Invalid chalange")
	}

	expected = []byte("Password:")
	resp, err = c.Next(expected)
	if bytes.Compare(resp, expected) != 0 {
		t.Error("Invalid initial response:", resp)
	}
}

func TestNewLoginServer(t *testing.T) {
	var authenticated = false
	s := sasl.NewLoginServer(func(username, password string) error {
		if username != "tim" {
			return errors.New("Invalid username: " + username)
		}
		if password != "tanstaaftanstaaf" {
			return errors.New("Invalid password: " + password)
		}

		authenticated = true
		return nil
	})

	challenge, done, err := s.Next(nil)
	if err != nil {
		t.Fatal("Error while starting server:", err)
	}
	if done {
		t.Fatal("Done after starting server")
	}
	if string(challenge) != "Username:" {
		t.Error("Invalid first challenge:", challenge)
	}

	challenge, done, err = s.Next([]byte("tim"))
	if err != nil {
		t.Fatal("Error while sending username:", err)
	}
	if done {
		t.Fatal("Done after sending username")
	}
	if string(challenge) != "Password:" {
		t.Error("Invalid challenge after sending username:", challenge)
	}

	challenge, done, err = s.Next([]byte("tanstaaftanstaaf"))
	if err != nil {
		t.Fatal("Error while sending password:", err)
	}
	if !done {
		t.Fatal("Authentication not finished after sending password")
	}
	if len(challenge) > 0 {
		t.Error("Invalid non-empty final challenge:", challenge)
	}

	if !authenticated {
		t.Error("Not authenticated")
	}

	// Tests with initial response field, as per RFC4422 section 3
	authenticated = false
	s = sasl.NewLoginServer(func(username, password string) error {
		if username != "tim" {
			return errors.New("Invalid username: " + username)
		}
		if password != "tanstaaftanstaaf" {
			return errors.New("Invalid password: " + password)
		}

		authenticated = true
		return nil
	})

	challenge, done, err = s.Next([]byte("tim"))
	if err != nil {
		t.Fatal("Error while sending username:", err)
	}
	if done {
		t.Fatal("Done after sending username")
	}
	if string(challenge) != "Password:" {
		t.Error("Invalid challenge after sending username:", string(challenge))
	}

	challenge, done, err = s.Next([]byte("tanstaaftanstaaf"))
	if err != nil {
		t.Fatal("Error while sending password:", err)
	}
	if !done {
		t.Fatal("Authentication not finished after sending password")
	}
	if len(challenge) > 0 {
		t.Error("Invalid non-empty final challenge:", challenge)
	}

	if !authenticated {
		t.Error("Not authenticated")
	}

	challenge, done, err = s.Next([]byte("unexpected"))
	if !errors.Is(err, sasl.ErrUnexpectedClientResponse) {
		t.Errorf("Unexpected response error = %v, want %v", err, sasl.ErrUnexpectedClientResponse)
	}
	if done {
		t.Error("Done after unexpected response")
	}
	if len(challenge) > 0 {
		t.Error("Invalid challenge after unexpected response:", challenge)
	}
}

func TestNewLoginServerAuthenticationError(t *testing.T) {
	wantErr := errors.New("authentication failed")
	s := sasl.NewLoginServer(func(username, password string) error {
		return wantErr
	})

	challenge, done, err := s.Next([]byte("tim"))
	if err != nil || done || string(challenge) != "Password:" {
		t.Fatalf("Initial response: challenge=%q done=%v err=%v", challenge, done, err)
	}

	challenge, done, err = s.Next([]byte("wrong-password"))
	if !errors.Is(err, wantErr) {
		t.Errorf("Authentication error = %v, want %v", err, wantErr)
	}
	if !done {
		t.Error("Authentication exchange did not finish after credential rejection")
	}
	if len(challenge) > 0 {
		t.Error("Invalid final challenge:", challenge)
	}
}
