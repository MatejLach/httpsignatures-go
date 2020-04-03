package httpsignatures

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha1Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultSha1Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultSha1Signer.headers, s.Headers)

	assert.Equal(t,
		"NDQ4NzQxNWYxMmRiZWEwNWFjYmI3NmQ5YjZhZGViNDE2NDkxZDY3OQ==",
		s.Signature,
	)
}

func TestSignSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultSha256Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultSha256Signer.headers, s.Headers)

	assert.Equal(t,
		"OTg4NWY1OWM1YjUxMGUxYmVmZjA3MjE0NDhkYTQ0ZGNkNDE5NjdhMTA4NjNkZjBlNmNkOTA5MzNlM2FhZWMwNQ==",
		s.Signature,
	)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}}

	err := DefaultSha1Signer.AuthRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	assert.NotEqual(t, "", r.Header.Get("date"))
}

func TestSignWithMissingHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	s := NewSigner(AlgorithmHmacSha1, "foo")

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}
