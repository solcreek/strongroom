// Sanitized upstream facts for operator logs only: an HTTP status and an allowlisted error code, never a message or body.
export interface Upstream { status: number; code?: string }
export class ServiceError extends Error {
  code: string; status: number; retryable: boolean; upstream?: Upstream;
  constructor(code: string, status: number, message: string, retryable = false) {
    super(message); this.code = code; this.status = status; this.retryable = retryable;
  }
}
export const invalid = () => new ServiceError('INVALID_REQUEST', 400, 'Request does not match the API schema.');
export const unavailable = () => new ServiceError('KMS_UNAVAILABLE', 503, 'Key service is unavailable.', true);
export const decryptFailed = () => new ServiceError('DECRYPT_FAILED', 400, 'Envelope could not be decrypted with this context.');
// Operator action required: retrying unchanged cannot succeed, and the envelope/context are not at fault.
export const accessDenied = () => new ServiceError('KMS_ACCESS_DENIED', 502, 'Key service rejected the service credentials or permissions.');
export const keyUnavailable = () => new ServiceError('KMS_KEY_UNAVAILABLE', 502, 'Configured KMS key is missing, disabled or unusable.');
