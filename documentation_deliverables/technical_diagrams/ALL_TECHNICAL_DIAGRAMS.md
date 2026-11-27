# SecureVault Technical Diagrams & Workflows

This document contains technical diagrams matching the actual implementation of the **SecureVault** codebase.

---

## Diagram 1: Overall SecureVault Architecture

```mermaid
flowchart TD
    subgraph ClientLayer["Frontend Client (React 19 + Vite)"]
        UI["Tailwind CSS Web Application"]
        Axios["Axios Interceptor (Bearer Token Session)"]
        UI --> Axios
    end

    subgraph APILayer["Backend REST API (Flask)"]
        ViteProxy["Vite Dev Reverse Proxy (:5173 -> :5000)"]
        CORS["Strict CORS Allowlist (localhost:5173)"]
        AuthBP["Auth Blueprint (/api/auth)"]
        AdminBP["Admin Blueprint (/api/admin)"]
        DocBP["Document Blueprint (/api/documents)"]
        AuditBP["Audit Blueprint (/api/audit)"]
        
        Axios --> ViteProxy --> CORS
        CORS --> AuthBP & AdminBP & DocBP & AuditBP
    end

    subgraph SecurityCore["Core Cryptographic & Authorization Services"]
        CryptoSvc["CryptoService (Singleton Orchestrator)"]
        BSW07["CharmEngine (BSW07 CP-ABE over BN254 Curve)"]
        Hybrid["HybridCipher (KEM via CP-ABE + DEM via AES-256-GCM)"]
        KeyStore["KeyStore (PBKDF2-HMAC-SHA256 + AES-256-GCM)"]
        AuditChain["AuditChain (Canonical JSON + HMAC-SHA256)"]
        AuthUtil["AuthUtils (PBKDF2 Passwords + HMAC-SHA256 Tokens)"]
        
        AuthBP & AdminBP & DocBP & AuditBP --> CryptoSvc
        CryptoSvc --> BSW07 & Hybrid & KeyStore & AuditChain
        AuthBP --> AuthUtil
    end

    subgraph StorageLayer["Persistence & Storage Layer"]
        SQLite[("SQLite (securevault.db)\n• users\n• user_keys (encrypted_sk)\n• documents (metadata & policy)\n• audit_logs (chained hashes)\n• system_epochs")]
        DiskDocs[("Encrypted Ciphertexts (/storage/encrypted/*.enc)")]
        DiskKeys[("Master Authority (/storage/keys/master_secret_key.enc)")]
        
        CryptoSvc --> SQLite
        Hybrid --> DiskDocs
        KeyStore --> DiskKeys
    end
```

---

## Diagram 2: User Login and Authentication Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant API as Auth API (/api/auth/login)
    participant DB as SQLite (users & user_keys)
    participant Crypto as CryptoService (Key Claim)
    participant Audit as AuditChain

    User->>API: POST /api/auth/login { username, password }
    API->>DB: SELECT * FROM users WHERE username = ?
    alt User Not Found or Password Invalid
        API->>Audit: record_audit_event(AUTH_LOGIN, FAILED)
        API-->>User: 401 Unauthorized
    else Valid Credentials (PBKDF2 constant-time check)
        alt pending_key_reissue == 1
            Note over API,Crypto: Asynchronous Key Claim on Login
            API->>Crypto: claim_pending_key(user_id, password)
            Crypto->>Crypto: keygen(PK, MK, updated_attrs + current_epoch)
            Crypto->>Crypto: encrypt_user_key(SK, password)
            Crypto->>DB: INSERT user_keys (v+1) & pending_key_reissue = 0
        end
        API->>API: generate_token(user_id, username, system_role) [HMAC-SHA256]
        API->>Audit: record_audit_event(AUTH_LOGIN, SUCCESS)
        API-->>User: 200 OK { token, user_profile, active_key }
    end
```

---

## Diagram 3: PDF Upload and Hybrid Encryption Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Uploader as Authorized User
    participant DocAPI as Document API (/api/documents/upload)
    participant Hybrid as HybridCipher
    participant BSW07 as CharmEngine (BSW07)
    participant Disk as Filesystem (/storage/encrypted/)
    participant DB as SQLite (documents)
    participant Audit as AuditChain

    Uploader->>DocAPI: POST /api/documents/upload (PDF bytes, access_policy, attach_epoch)
    DocAPI->>DocAPI: Verify Authorization Bearer token
    alt attach_epoch is true
        DocAPI->>DocAPI: final_policy = (access_policy) AND Epoch:<current_epoch>
    end
    DocAPI->>Hybrid: encrypt_document(PK, file_bytes, final_policy)
    Hybrid->>BSW07: Sample random GT element M (KEM secret)
    Hybrid->>Hybrid: AES_key = SHA-256(str(M))
    Hybrid->>Hybrid: AES-256-GCM.encrypt(file_bytes) -> aes_ciphertext, nonce, tag
    Hybrid->>BSW07: cpabe.encrypt(PK, M, final_policy) -> cpabe_ciphertext
    Hybrid-->>DocAPI: Return package { cpabe_ciphertext, aes_ciphertext, nonce, tag }
    DocAPI->>Disk: Write aes_ciphertext bytes to <uuid>.enc
    DocAPI->>DB: INSERT INTO documents (stored_filename, cpabe_ciphertext, nonce, tag, epoch)
    DocAPI->>Audit: record_audit_event(DOC_UPLOAD, SUCCESS)
    DocAPI-->>Uploader: 201 Created { doc_id, filename, access_policy, epoch }
```

---

## Diagram 4: CP-ABE Authorization and Decryption Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Decryptor as Requesting User
    participant DocAPI as Document API (/api/documents/:id/decrypt)
    participant KeyStore as KeyStore
    participant BSW07 as CharmEngine (BSW07)
    participant Hybrid as HybridCipher
    participant Audit as AuditChain

    Decryptor->>DocAPI: POST /api/documents/:id/decrypt { password }
    DocAPI->>DocAPI: Authenticate user session token
    DocAPI->>DocAPI: Fetch document metadata & active user encrypted_sk envelope
    DocAPI->>KeyStore: decrypt_user_key(encrypted_sk, password)
    alt Invalid Password
        DocAPI->>Audit: record_audit_event(DECRYPT_FAILED, FAILED, "Invalid passphrase")
        DocAPI-->>Decryptor: 400 Bad Request ("Could not unlock private key")
    else Private Key Unlocked in Transient RAM
        DocAPI->>Hybrid: decrypt_document(PK, user_sk, encrypted_package)
        Hybrid->>BSW07: cpabe.decrypt(PK, user_sk, cpabe_ciphertext)
        alt User Attributes Do NOT Satisfy Policy Tree
            BSW07-->>Hybrid: Pairing reconstruction returns None (Mathematical Denial)
            Hybrid-->>DocAPI: raise AccessDeniedError
            DocAPI->>Audit: record_audit_event(DECRYPT_DENIED, DENIED, "Policy unsatisfied")
            DocAPI-->>Decryptor: 403 Forbidden ("Access Denied: Attributes do not satisfy policy")
        else Attributes Satisfy Policy Tree
            BSW07-->>Hybrid: Recovered GT element M
            Hybrid->>Hybrid: AES_key = SHA-256(str(M))
            Hybrid->>Hybrid: AES-256-GCM.decrypt_and_verify(aes_ciphertext, tag)
            alt Tampering Detected (Tag mismatch)
                Hybrid-->>DocAPI: raise TamperError
                DocAPI->>Audit: record_audit_event(DECRYPT_FAILED, FAILED, "AES tag failure")
                DocAPI-->>Decryptor: 400 Bad Request ("Ciphertext corrupted or tampered")
            else Valid Decryption
                Hybrid-->>DocAPI: Return exact plaintext PDF bytes
                DocAPI->>Audit: record_audit_event(DECRYPT_SUCCESS, SUCCESS)
                DocAPI-->>Decryptor: 200 OK (PDF bytes or base64 download)
            end
        end
    end
```

---

## Diagram 5: Epoch-Based Revocation Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Security Admin
    participant EpochAPI as Admin API (/api/admin/epoch)
    participant CryptoSvc as CryptoService
    participant DB as SQLite (system_epochs, users, documents)
    participant Disk as Storage (/storage/encrypted/)
    participant Alice as Authorized User (Alice)
    participant Bob as Revoked User (Bob)

    Admin->>EpochAPI: POST /api/admin/epoch/advance { reason: "User Bob Revoked" }
    EpochAPI->>CryptoSvc: advance_system_epoch(admin_id, reason)
    CryptoSvc->>DB: INSERT system_epochs (epoch=2, status='DECLARED')
    CryptoSvc->>DB: UPDATE users SET pending_key_reissue = 1
    EpochAPI-->>Admin: 200 OK { current_epoch: 2 }

    Note over Admin,Disk: Staged Document Re-encryption Phase
    Admin->>EpochAPI: POST /api/admin/epoch/reencrypt/:id { password }
    EpochAPI->>CryptoSvc: reencrypt_document(doc_id, target_epoch=2)
    CryptoSvc->>CryptoSvc: Authorized CP-ABE Decrypt original PDF
    CryptoSvc->>CryptoSvc: Encrypt under updated policy: ({policy}) AND Epoch:2
    CryptoSvc->>Disk: Write <new_uuid>.staged.enc
    CryptoSvc->>Disk: Rename to <new_uuid>.enc
    CryptoSvc->>DB: UPDATE documents SET stored_filename, policy, epoch=2
    CryptoSvc->>Disk: DELETE old <prev_uuid>.enc
    EpochAPI-->>Admin: 200 OK (Document re-encrypted to Epoch 2)

    Note over Bob: Mathematical Revocation Demonstration
    Bob->>DocAPI: Decrypt with Old Key v1 (Epoch:1)
    DocAPI-->>Bob: 403 Forbidden (BSW07 pairing failure: Epoch 1 != Epoch 2)

    Note over Alice: Key Renewal Demonstration
    Alice->>EpochAPI: POST /api/auth/claim-key { password }
    EpochAPI-->>Alice: Key v2 Issued embedding [Role:Engineer, Clearance:Level-3, Epoch:2]
    Alice->>DocAPI: Decrypt with New Key v2 (Epoch:2)
    DocAPI-->>Alice: 200 OK (Decryption SUCCESS - Document Recovered)
```

---

## Diagram 6: HMAC-SHA256 Audit Log Chaining Architecture

```mermaid
flowchart LR
    subgraph GenesisBlock["Genesis State"]
        G0["Genesis Hash\n0000...0000 (64 zeros)"]
    end

    subgraph Event1["Audit Record #1"]
        direction TB
        C1["Canonical Representation #1\n• sequence_number: 1\n• timestamp: 2026-11-10 10:00:00\n• user_id: 1\n• username: admin\n• action: AUTH_LOGIN\n• status: SUCCESS\n• details: User logged in\n• ip_address: 127.0.0.1\n• previous_hash: 0000...0000"]
        H1["HMAC-SHA256(K_audit, C1)\n= record_hash #1"]
        C1 --> H1
    end

    subgraph Event2["Audit Record #2"]
        direction TB
        C2["Canonical Representation #2\n• sequence_number: 2\n• timestamp: 2026-11-10 10:02:15\n• user_id: 1\n• username: admin\n• action: DOC_UPLOAD\n• status: SUCCESS\n• details: Uploaded report.pdf\n• ip_address: 127.0.0.1\n• previous_hash: record_hash #1"]
        H2["HMAC-SHA256(K_audit, C2)\n= record_hash #2"]
        C2 --> H2
    end

    subgraph Event3["Audit Record #3"]
        direction TB
        C3["Canonical Representation #3\n• sequence_number: 3\n• timestamp: 2026-11-10 10:05:30\n• user_id: 2\n• username: bob\n• action: DECRYPT_DENIED\n• status: DENIED\n• details: CP-ABE denial\n• ip_address: 192.168.1.20\n• previous_hash: record_hash #2"]
        H3["HMAC-SHA256(K_audit, C3)\n= record_hash #3"]
        C3 --> H3
    end

    G0 -->|previous_hash| C1
    H1 -->|previous_hash| C2
    H2 -->|previous_hash| C3

    subgraph VerificationEngine["Verification Engine (verify_chain_integrity)"]
        V["1. Check Sequence: 1, 2, 3... Contiguous\n2. Check Link: Record[i].previous_hash == Record[i-1].record_hash\n3. Check Signature: HMAC(K_audit, Canon(Record[i])) == record_hash[i]\n\nResult: 100% Intact OR Tampering Detected (Mod, Swap, Del)"]
    end

    H3 -.-> V
```
