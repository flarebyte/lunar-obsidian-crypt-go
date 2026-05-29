package lunarcrypt

import "testing"

func TestStableErrorStepValues(t *testing.T) {
	tests := map[string]string{
		"StepSignIDStore":             StepSignIDStore,
		"StepSignIDValidatePayload":   StepSignIDValidatePayload,
		"StepSignIDSign":              StepSignIDSign,
		"StepVerifyIDExtractToken":    StepVerifyIDExtractToken,
		"StepVerifyIDStore":           StepVerifyIDStore,
		"StepVerifyIDDecodeToken":     StepVerifyIDDecodeToken,
		"StepVerifyIDValidatePayload": StepVerifyIDValidatePayload,
		"StepVerifyIDVerifyScope":     StepVerifyIDVerifyScope,
		"StepVerifyIDVerifyToken":     StepVerifyIDVerifyToken,
	}

	want := map[string]string{
		"StepSignIDStore":             "sign-id/store",
		"StepSignIDValidatePayload":   "sign-id/validate-payload",
		"StepSignIDSign":              "sign-id/sign",
		"StepVerifyIDExtractToken":    "verify-id/extract-token",
		"StepVerifyIDStore":           "verify-id/store",
		"StepVerifyIDDecodeToken":     "verify-id/decode-token",
		"StepVerifyIDValidatePayload": "verify-id/validate-payload",
		"StepVerifyIDVerifyScope":     "verify-id/verify-scope",
		"StepVerifyIDVerifyToken":     "verify-id/verify-token",
	}

	for name, got := range tests {
		if got != want[name] {
			t.Fatalf("%s = %q, want %q", name, got, want[name])
		}
	}
}

func TestResultConstructors(t *testing.T) {
	success := Succeed(42)
	if success.Status != Success {
		t.Fatalf("success status = %q, want %q", success.Status, Success)
	}
	if success.Value != 42 {
		t.Fatalf("success value = %d, want 42", success.Value)
	}
	if success.Error != nil {
		t.Fatalf("success error = %#v, want nil", success.Error)
	}

	failure := Fail[int](CryptError{Step: StepSignIDStore, Message: "unsupported prefix"})
	if failure.Status != Failure {
		t.Fatalf("failure status = %q, want %q", failure.Status, Failure)
	}
	if failure.Value != 0 {
		t.Fatalf("failure value = %d, want zero value", failure.Value)
	}
	if failure.Error == nil {
		t.Fatal("failure error = nil, want error")
	}
	if failure.Error.Step != StepSignIDStore {
		t.Fatalf("failure step = %q, want %q", failure.Error.Step, StepSignIDStore)
	}
}
