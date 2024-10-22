# Cross-Platform JWT Implementation Guide

This guide explains how to use the JWT (JSON Web Token) implementations across different platforms (Oracle, SQL Server, Classic ASP, .NET) with both symmetric and asymmetric key support.

## Table of Contents
- [Understanding JWT](#understanding-jwt)
- [Symmetric vs. Asymmetric Keys](#symmetric-vs-asymmetric-keys)
- [Cross-Platform Compatibility](#cross-platform-compatibility)
- [Implementation Guide](#implementation-guide)
  - [Oracle PL/SQL](#oracle-plsql)
  - [SQL Server](#sql-server)
  - [Classic ASP](#classic-asp)
  - [.NET](#net)
- [Token Structure](#token-structure)
- [Security Considerations](#security-considerations)

## Understanding JWT

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. JWTs can be:
- Signed (JWS - JSON Web Signature)
- Encrypted (JWE - JSON Web Encryption)

Our implementation focuses on signed tokens using either:
- HMAC-SHA256 (symmetric)
- RSA-SHA256 (asymmetric)

## Symmetric vs. Asymmetric Keys

### Symmetric Keys (HS256)
- Uses the same secret key for both signing and verification
- Faster performance
- Simpler to implement
- Best for single-organization scenarios
- Secret key must be securely shared between all parties

Example:
```plaintext
Secret Key: "your-secret-key-here"
```

### Asymmetric Keys (RS256)
- Uses private key for signing and public key for verification
- More complex but more secure for distributed systems
- Private key never needs to be shared
- Suitable for multi-organization scenarios
- Allows public verification without compromising signing capability

Example key pair:
```plaintext
Private Key (for signing):
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJT...
-----END PRIVATE KEY-----

Public Key (for verification):
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU...
-----END PUBLIC KEY-----
```

## Cross-Platform Compatibility

All implementations use the same token format and algorithms, ensuring cross-platform compatibility. A token generated on any platform can be validated on any other platform as long as the correct keys are available.

Token structure across all platforms:
```
header.payload.signature
```

## Implementation Guide

### Oracle PL/SQL

Symmetric Key Usage:
```sql
-- Create token
DECLARE
  v_token VARCHAR2(4000);
BEGIN
  v_token := JSON_TOKEN_PKG.CREATE_TOKEN(
    p_username => 'john.doe',
    p_claims => 'admin,user'
  );
END;

-- Validate token
DECLARE
  v_is_valid BOOLEAN;
BEGIN
  v_is_valid := JSON_TOKEN_PKG.IS_VALID(v_token);
END;
```

Asymmetric Key Usage:
```sql
-- Create token
DECLARE
  v_token VARCHAR2(4000);
BEGIN
  v_token := JSON_TOKEN_PKG.CREATE_TOKEN_RSA(
    p_username => 'john.doe',
    p_claims => 'admin,user',
    p_private_key => 'your-private-key-here'
  );
END;

-- Validate token
DECLARE
  v_is_valid BOOLEAN;
BEGIN
  v_is_valid := JSON_TOKEN_PKG.IS_VALID_RSA(
    p_token => v_token,
    p_public_key => 'your-public-key-here'
  );
END;
```

### SQL Server

Symmetric Key Usage:
```sql
-- Create token
DECLARE @token VARCHAR(MAX)
SET @token = jwt.create_token_symmetric(
    'john.doe',
    'admin,user',
    'your-secret-key-here'
)

-- Validate token
DECLARE @is_valid BIT
SET @is_valid = jwt.is_valid_symmetric(@token, 'your-secret-key-here')
```

Asymmetric Key Usage:
```sql
-- First, create and store keys
EXEC jwt.manage_keys 
    @action = 'CREATE_ASYMMETRIC',
    @key_name = 'MyKey'

-- Create token
DECLARE @token VARCHAR(MAX)
SET @token = jwt.create_token_asymmetric(
    'john.doe',
    'admin,user',
    @key_id
)

-- Validate token
DECLARE @is_valid BIT
SET @is_valid = jwt.is_valid_asymmetric(@token, @key_id)
```

### Classic ASP

```vbscript
' Initialize JWT class
Dim jwt
Set jwt = New JWT

' Symmetric Key Usage
jwt.Secret = "your-secret-key-here"
Dim token
token = jwt.CreateToken("john.doe", "admin,user")
Dim isValid
isValid = jwt.IsValid(token)

' Asymmetric Key Usage
jwt.PrivateKey = "your-private-key-in-xml-format"
jwt.PublicKey = "your-public-key-in-xml-format"
token = jwt.CreateTokenRSA("john.doe", "admin,user")
isValid = jwt.IsValidRSA(token)
```

### .NET

```csharp
// Symmetric Key Usage
var jwtService = new JwtService(symmetricKey: "your-secret-key-here");
var token = jwtService.CreateTokenSymmetric("john.doe", "admin,user");

TokenValidationResult result;
bool isValid = jwtService.ValidateTokenSymmetric(token, out result);

// Asymmetric Key Usage
var jwtServiceRsa = new JwtService(
    rsaPrivateKey: "your-private-key-pem",
    rsaPublicKey: "your-public-key-pem"
);
var tokenRsa = jwtServiceRsa.CreateTokenAsymmetric("john.doe", "admin,user");
bool isValidRsa = jwtServiceRsa.ValidateTokenAsymmetric(tokenRsa, out result);
```

## Token Structure

All implementations create tokens with the following structure:

```javascript
// Header
{
  "alg": "HS256",  // or "RS256" for asymmetric
  "typ": "JWT"
}

// Payload
{
  "username": "john.doe",
  "claims": "admin,user",
  "exp": 1234567890  // Unix timestamp
}
```

## Security Considerations

1. Key Storage
   - Never store symmetric keys in code
   - Keep private keys secure and never share them
   - Use appropriate key management systems

2. Token Handling
   - Always validate tokens before trusting them
   - Check expiration times
   - Verify signatures
   - Don't store sensitive data in tokens

3. Cross-Platform Best Practices
   - Use the same key length across platforms
   - Keep token expiration times consistent
   - Implement proper error handling
   - Regular key rotation

4. Algorithm Selection
   - HS256 (symmetric) for single-organization scenarios
   - RS256 (asymmetric) for multi-organization scenarios
   - Consider key size vs performance tradeoffs

## Example of Cross-Platform Usage

Generate a token on Oracle and validate it on .NET:

```sql
-- Oracle: Generate token
DECLARE
  v_token VARCHAR2(4000);
BEGIN
  v_token := JSON_TOKEN_PKG.CREATE_TOKEN(
    p_username => 'john.doe',
    p_claims => 'admin,user'
  );
END;
```

```csharp
// .NET: Validate the Oracle-generated token
var jwtService = new JwtService(symmetricKey: "your-secret-key-here");
TokenValidationResult result;
bool isValid = jwtService.ValidateTokenSymmetric(oracleGeneratedToken, out result);
```

The same token can be validated on SQL Server:

```sql
-- SQL Server: Validate the Oracle-generated token
DECLARE @is_valid BIT
SET @is_valid = jwt.is_valid_symmetric(@oracle_generated_token, 'your-secret-key-here')
```

As long as the same keys are used, tokens are completely interoperable between platforms.
