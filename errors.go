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
