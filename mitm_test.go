package mitm

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBypassHandlerHTTP(t *testing.T) {
	tests := []struct {
		Code int
		Body string
	}{
		{Code: http.StatusOK, Body: "Hello, world"},
		{Code: http.StatusNotFound, Body: "Not found"},
	}

	var statusCode int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	for _, ts := range tests {
		statusCode = ts.Code
		body = ts.Body

		r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		w := httptest.NewRecorder()

		BypassHandler(w, r)

		if w.Code != statusCode {
			t.Errorf("Expect: %d, Got: %d - %s", statusCode, w.Code, w.Body.String())
			return
		}
		if w.Body.String() != body {
			t.Errorf("Body not match")
			return
		}
	}

}
