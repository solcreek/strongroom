export class ServiceError extends Error {
  code: string; status: number; retryable: boolean;
  constructor(code: string, status: number, message: string, retryable = false) {
    super(message); this.code = code; this.status = status; this.retryable = retryable;
  }
}
export const invalid = () => new ServiceError('INVALID_REQUEST', 400, 'Request does not match the API schema.');
export const unavailable = () => new ServiceError('KMS_UNAVAILABLE', 503, 'Key service is unavailable.', true);
export const decryptFailed = () => new ServiceError('DECRYPT_FAILED', 400, 'Envelope could not be decrypted with this context.');
