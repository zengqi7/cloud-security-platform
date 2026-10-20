package blob

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestS3IntegrityAndEncryptedWrite(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX"}`)
	var stored []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/evidence/prefix/object.json" {
			t.Errorf("path %s", r.URL.Path)
		}
		switch r.Method {
		case "PUT":
			if r.Header.Get("X-Amz-Server-Side-Encryption") != "AES256" {
				t.Error("missing encryption")
			}
			stored, _ = io.ReadAll(r.Body)
		case "GET":
			w.Write(stored)
		case "DELETE":
			stored = nil
		}
	}))
	defer srv.Close()
	client := s3.New(s3.Options{Region: "test", BaseEndpoint: aws.String(srv.URL), UsePathStyle: true, HTTPClient: srv.Client(), Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})
	s := &S3{Client: client, Bucket: "evidence", Prefix: "prefix/"}
	ctx := context.Background()
	if err := s.Put(ctx, "object.json", raw); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "object.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if err := Verify(got, digest); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("tampered"), digest); err == nil {
		t.Fatal("tampering accepted")
	}
	if err := s.Delete(ctx, "object.json"); err != nil || stored != nil {
		t.Fatalf("delete: %v", err)
	}
}
func TestEndpointRequiresHTTPS(t *testing.T) {
	t.Setenv("OBJECT_STORE_BUCKET", "evidence")
	t.Setenv("OBJECT_STORE_REGION", "test")
	t.Setenv("OBJECT_STORE_ENDPOINT", "http://example.com")
	if _, err := FromEnv(context.Background()); err == nil {
		t.Fatal("accepted plaintext endpoint")
	}
}
