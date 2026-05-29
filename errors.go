/*
Purpose: Centralizes stable operation step identifiers and result constructors for API success and failure responses.
Responsibilities:
- Name sign and verify failure steps, construct success results, and attach CryptError details to failure results.
Architecture notes:
- Step strings are part of the observable contract used by tests, docs, and callers; avoid renaming without a compatibility decision.
- Result construction stays tiny here so domain files can return consistent envelopes without duplicating status wiring.
*/
package lunarcrypt

const (
	StepSignIDStore           = "sign-id/store"
	StepSignIDValidatePayload = "sign-id/validate-payload"
	StepSignIDSign            = "sign-id/sign"

	StepVerifyIDExtractToken    = "verify-id/extract-token"
	StepVerifyIDStore           = "verify-id/store"
	StepVerifyIDDecodeToken     = "verify-id/decode-token"
	StepVerifyIDValidatePayload = "verify-id/validate-payload"
	StepVerifyIDVerifyScope     = "verify-id/verify-scope"
	StepVerifyIDVerifyToken     = "verify-id/verify-token"
)

func Succeed[T any](value T) Result[T] {
	return Result[T]{
		Status: Success,
		Value:  value,
	}
}

func Fail[T any](err CryptError) Result[T] {
	return Result[T]{
		Status: Failure,
		Error:  &err,
	}
}
