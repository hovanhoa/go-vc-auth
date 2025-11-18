## Go VC Auth SDK

This repository contains a small Go SDK for working with **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**.

- **`model.go`**: Core data models for credential documents (contexts, subjects, schemas, status, etc.).
- **`auth.go`**: High-level `Auth` interface for creating and verifying VP tokens built from VC documents.
- **`provider.go`**: `Provider` interface abstraction for signing payloads with a private key.

The source code is intentionally minimal to serve as a starting point for building a full VC/VP-based authentication flow in Go.

