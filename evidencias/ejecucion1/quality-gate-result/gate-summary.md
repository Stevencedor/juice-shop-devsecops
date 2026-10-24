# Resultado del Quality Gate - 2026-10-24

**Decisión global: ⛔ BLOCK**  (la liberación se detiene)

| Gate | Control | Herramienta | Resultado | Detalle |
|---|---|---|---|---|
| QG-01 | Secretos | gitleaks | ⛔ BLOCK | CRITICAL/HIGH/MEDIUM/LOW: 225 (máximo 0) -> BLOCK |
| QG-02 | SAST | semgrep | ⛔ BLOCK | CRITICAL/HIGH: 3 (máximo 0) -> BLOCK<br>MEDIUM: 17 (máximo 0) -> WARN |
| QG-03 | SCA | trivy-sca | ⛔ BLOCK | CRITICAL: 9 (máximo 0) -> BLOCK<br>HIGH (fixed): 28 (máximo 0) -> BLOCK<br>HIGH (unfixed): 1 (máximo 0) -> WARN<br>MEDIUM: 32 (máximo 0) -> WARN |
| QG-04 | Contenedor | trivy-image | ⛔ BLOCK | CRITICAL: 9 (máximo 0) -> BLOCK<br>HIGH (fixed): 26 (máximo 0) -> BLOCK<br>HIGH (unfixed): 1 (máximo 0) -> WARN<br>MEDIUM: 52 (máximo 0) -> WARN |
| QG-05 | IaC / configuración | trivy-iac | ⛔ BLOCK | CRITICAL/HIGH: 25 (máximo 0) -> BLOCK<br>MEDIUM: 4 (máximo 0) -> WARN |
| QG-06 | SBOM | sbom | ✅ PASS | 2744 componentes en el SBOM (mínimo 1) |
| QG-07 | DAST | zap | ⛔ BLOCK | SIN EVIDENCIA: no existe el reporte zap.json |
| QG-08 | Gobierno de excepciones | exceptions | ✅ PASS | todas las excepciones son válidas (o no hay excepciones) |

### QG-01 - principales hallazgos que bloquean

- `generic-api-key` [HIGH] test/api/helpers/passkey.ts:56 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] test/api/passkey.test.ts:21 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] data/static/users.yml:296 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] frontend/src/app/manage-passkeys/passkey-providers.ts:9 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] frontend/src/app/manage-passkeys/passkey-providers.ts:11 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] frontend/src/app/manage-passkeys/passkey-providers.ts:20 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] test/api/passkey.test.ts:339 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `generic-api-key` [HIGH] test/api/passkey.test.ts:464 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- `private-key` [HIGH] test/files/passkeyVictimCredential.json:4 - Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.
- `generic-api-key` [HIGH] test/api/erasure-request.test.ts:94 - Detected a Generic API Key, potentially exposing access to various services and sensitive operations.
- ... y 215 mas (ver el reporte JSON completo)

### QG-02 - principales hallazgos que bloquean

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` [HIGH] routes/login.ts:34 - Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized.
- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` [HIGH] routes/search.ts:23 - Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized.
- `javascript.lang.security.audit.code-string-concat.code-string-concat` [HIGH] routes/userProfile.ts:65 - Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in t

### QG-03 - principales hallazgos que bloquean

- `CVE-2023-46233` [CRITICAL] package-lock.json - crypto-js 3.3.0 - crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
- `CVE-2026-71851` [CRITICAL] package-lock.json - crypto-js 3.3.0 - crypto-js: crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
- `CVE-2026-101894` [CRITICAL] package-lock.json - decompress 4.2.1 - @xhmikosr/decompress: @xhmikosr/decompress: Path traversal via symlink chain
- `CVE-2026-53486` [CRITICAL] package-lock.json - decompress 4.2.1 - decompress: @xhmikosr/decompress: Decompress: Arbitrary file read/write via crafted archive extraction
- `CVE-2015-9235` [CRITICAL] package-lock.json - jsonwebtoken 0.1.0 - nodejs-jsonwebtoken: verification step bypass with an altered token
- `CVE-2015-9235` [CRITICAL] package-lock.json - jsonwebtoken 0.4.0 - nodejs-jsonwebtoken: verification step bypass with an altered token
- `CVE-2019-10744` [CRITICAL] package-lock.json - lodash 2.4.2 - nodejs-lodash: prototype pollution in defaultsDeep function leading to modifying properties
- `GHSA-5mrr-rgp6-x4gr` [CRITICAL] package-lock.json - marsdb 0.6.11 - Command Injection in marsdb
- `CVE-2026-59873` [CRITICAL] package-lock.json - tar 6.2.1 - tar: node-tar: Denial of Service via crafted gzip bomb
- `CVE-2026-112942` [HIGH] frontend/package-lock.json - vite 8.3.0 - launch-editor: launch-editor: Command injection via improper file path validation
- ... y 27 mas (ver el reporte JSON completo)

### QG-04 - principales hallazgos que bloquean

- `CVE-2023-46233` [CRITICAL] Node.js - crypto-js 3.3.0 - crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
- `CVE-2026-71851` [CRITICAL] Node.js - crypto-js 3.3.0 - crypto-js: crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
- `CVE-2026-101894` [CRITICAL] Node.js - decompress 4.2.1 - @xhmikosr/decompress: @xhmikosr/decompress: Path traversal via symlink chain
- `CVE-2026-53486` [CRITICAL] Node.js - decompress 4.2.1 - decompress: @xhmikosr/decompress: Decompress: Arbitrary file read/write via crafted archive extraction
- `CVE-2015-9235` [CRITICAL] Node.js - jsonwebtoken 0.1.0 - nodejs-jsonwebtoken: verification step bypass with an altered token
- `CVE-2015-9235` [CRITICAL] Node.js - jsonwebtoken 0.4.0 - nodejs-jsonwebtoken: verification step bypass with an altered token
- `CVE-2019-10744` [CRITICAL] Node.js - lodash 2.4.2 - nodejs-lodash: prototype pollution in defaultsDeep function leading to modifying properties
- `GHSA-5mrr-rgp6-x4gr` [CRITICAL] Node.js - marsdb 0.6.11 - Command Injection in marsdb
- `CVE-2026-59873` [CRITICAL] Node.js - tar 6.2.1 - tar: node-tar: Denial of Service via crafted gzip bomb
- `NSWG-ECO-428` [HIGH] Node.js - base64url 0.0.6 - Out-of-bounds Read
- ... y 25 mas (ver el reporte JSON completo)

### QG-05 - principales hallazgos que bloquean

- `AWS-0037` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_1.tf - EFS Encryption has not been enabled
- `AWS-0052` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_1.tf - Load balancers should drop invalid headers
- `AWS-0053` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_1.tf - Load balancer is exposed to the internet.
- `AWS-0054` [CRITICAL] data/static/codefixes/iacLeakedKeyChallenge_1.tf - Use of plain HTTP.
- `AWS-0104` [CRITICAL] data/static/codefixes/iacLeakedKeyChallenge_1.tf - A security group rule should not allow unrestricted egress to any IP address.
- `AWS-0104` [CRITICAL] data/static/codefixes/iacLeakedKeyChallenge_1.tf - A security group rule should not allow unrestricted egress to any IP address.
- `AWS-0104` [CRITICAL] data/static/codefixes/iacLeakedKeyChallenge_1.tf - A security group rule should not allow unrestricted egress to any IP address.
- `AWS-0164` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_1.tf - Instances in a subnet should not receive a public IP address by default.
- `AWS-0037` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_2.tf - EFS Encryption has not been enabled
- `AWS-0052` [HIGH] data/static/codefixes/iacLeakedKeyChallenge_2.tf - Load balancers should drop invalid headers
- ... y 15 mas (ver el reporte JSON completo)
