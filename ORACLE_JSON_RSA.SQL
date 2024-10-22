CREATE OR REPLACE PACKAGE JSON_TOKEN_PKG AS
  /* Original symmetric key functions */
  FUNCTION CREATE_TOKEN(
    p_username IN VARCHAR2,
    p_claims IN VARCHAR2
  ) RETURN VARCHAR2;
  
  FUNCTION IS_VALID(
    p_token IN VARCHAR2
  ) RETURN BOOLEAN;
  
  FUNCTION GET_CLAIMS(
    p_token IN VARCHAR2
  ) RETURN VARCHAR2;
  
  FUNCTION HAS_CLAIM(
    p_token IN VARCHAR2,
    p_claim IN VARCHAR2
  ) RETURN BOOLEAN;
  
  /* New asymmetric key functions */
  FUNCTION CREATE_TOKEN_RSA(
    p_username IN VARCHAR2,
    p_claims IN VARCHAR2,
    p_private_key IN VARCHAR2
  ) RETURN VARCHAR2;
  
  FUNCTION IS_VALID_RSA(
    p_token IN VARCHAR2,
    p_public_key IN VARCHAR2
  ) RETURN BOOLEAN;
END JSON_TOKEN_PKG;
/

CREATE OR REPLACE PACKAGE BODY JSON_TOKEN_PKG AS
  -- Existing constants
  c_secret CONSTANT VARCHAR2(100) := 'your-secret-key-here';
  
  -- Keep all existing private functions (base64_encode, base64_decode, split_string)
  -- ... [previous implementation remains unchanged] ...
  
  -- New private function for RSA signing
  FUNCTION sign_rsa(
    p_input IN VARCHAR2,
    p_private_key IN VARCHAR2
  ) RETURN RAW IS
    l_key_der RAW(2000);
    l_signature RAW(2000);
  BEGIN
    -- Convert PEM private key to DER format
    l_key_der := UTL_RAW.CAST_TO_RAW(p_private_key);
    
    -- Sign the input using RSA-SHA256
    l_signature := DBMS_CRYPTO.SIGN(
      src => UTL_RAW.CAST_TO_RAW(p_input),
      private_key => l_key_der,
      private_key_format => DBMS_CRYPTO.KEY_TYPE_RSA,
      sign_algorithm => DBMS_CRYPTO.SIGN_SHA256_RSA
    );
    
    RETURN l_signature;
  END;
  
  -- New private function for RSA verification
  FUNCTION verify_rsa(
    p_input IN VARCHAR2,
    p_signature IN RAW,
    p_public_key IN VARCHAR2
  ) RETURN BOOLEAN IS
    l_key_der RAW(2000);
  BEGIN
    -- Convert PEM public key to DER format
    l_key_der := UTL_RAW.CAST_TO_RAW(p_public_key);
    
    -- Verify the signature
    RETURN DBMS_CRYPTO.VERIFY(
      src => UTL_RAW.CAST_TO_RAW(p_input),
      signature => p_signature,
      public_key => l_key_der,
      public_key_format => DBMS_CRYPTO.KEY_TYPE_RSA,
      sign_algorithm => DBMS_CRYPTO.SIGN_SHA256_RSA
    ) = 1;
  END;
  
  -- Implementation of new public functions
  FUNCTION CREATE_TOKEN_RSA(
    p_username IN VARCHAR2,
    p_claims IN VARCHAR2,
    p_private_key IN VARCHAR2
  ) RETURN VARCHAR2 IS
    l_header VARCHAR2(32767);
    l_payload VARCHAR2(32767);
    l_signature VARCHAR2(32767);
    l_token VARCHAR2(32767);
  BEGIN
    -- Create header (note the change in algorithm)
    l_header := '{"alg":"RS256","typ":"JWT"}';
    
    -- Create payload
    l_payload := '{' ||
      '"username":"' || p_username || '",' ||
      '"claims":"' || p_claims || '",' ||
      '"exp":' || TO_CHAR(UNIX_TIMESTAMP + 3600) ||
    '}';
    
    -- Encode header and payload
    l_header := base64_encode(l_header);
    l_payload := base64_encode(l_payload);
    
    -- Create signature using RSA
    l_signature := base64_encode(
      sign_rsa(
        l_header || '.' || l_payload,
        p_private_key
      )
    );
    
    -- Combine all parts
    l_token := l_header || '.' || l_payload || '.' || l_signature;
    
    RETURN l_token;
  END;
  
  FUNCTION IS_VALID_RSA(
    p_token IN VARCHAR2,
    p_public_key IN VARCHAR2
  ) RETURN BOOLEAN IS
    l_parts t_string_table;
    l_header VARCHAR2(32767);
    l_payload VARCHAR2(32767);
    l_signature RAW(2000);
    l_exp NUMBER;
  BEGIN
    -- Split token
    l_parts := split_string(p_token, '.');
    
    IF l_parts.COUNT != 3 THEN
      RETURN FALSE;
    END IF;
    
    l_header := l_parts(1);
    l_payload := l_parts(2);
    
    -- Convert base64 signature to RAW
    l_signature := UTL_ENCODE.BASE64_DECODE(
      UTL_RAW.CAST_TO_RAW(l_parts(3))
    );
    
    -- Verify signature using RSA
    IF NOT verify_rsa(
      l_header || '.' || l_payload,
      l_signature,
      p_public_key
    ) THEN
      RETURN FALSE;
    END IF;
    
    -- Check expiration
    l_payload := base64_decode(l_payload);
    l_exp := TO_NUMBER(REGEXP_SUBSTR(l_payload, '"exp":(\d+)', 1, 1, NULL, 1));
    
    RETURN l_exp > UNIX_TIMESTAMP;
  END;
  
  -- Keep all existing public function implementations
  -- ... [previous implementations remain unchanged] ...
  
END JSON_TOKEN_PKG;
/
