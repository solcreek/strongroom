# Strongroom

Strongroom is an encryption toolkit in development for applications that accept
user-provided API keys and other credentials that must be retrieved securely.

The planned architecture uses a shared Rust core, with WebAssembly for Cloudflare
Workers and native Rust for container deployments. Managed key provider support
is planned for AWS KMS, Google Cloud KMS, and Vault / OpenBao Transit.

## Development status

This initial release establishes the package identity for the Strongroom project.
It contains documentation only. No encryption implementation, client SDK, or KMS
integration is included in this release.

Do not use this release to store or protect credentials. A usable API will be
introduced in a future version.
