-- Create a schema for JWT functions
IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'jwt')
BEGIN
    EXEC ('CREATE SCHEMA jwt')
END
GO

-- Helper function to encode base64url
CREATE OR ALTER FUNCTION jwt.base64_encode
(
    @input VARBINARY(MAX)
)
RETURNS VARCHAR(MAX)
AS
BEGIN
    DECLARE @result VARCHAR(MAX)
    SET @result = CAST('' AS XML).value('xs:base64Binary(sql:variable("@input"))', 'VARCHAR(MAX)')
    -- Convert to base64url
    SET @result = REPLACE(REPLACE(REPLACE(@result, '+', '-'), '/', '_'), '=', '')
    RETURN @result
END
GO

-- Helper function to decode base64url
CREATE OR ALTER FUNCTION jwt.base64_decode
(
    @input VARCHAR(MAX)
)
RETURNS VARBINARY(MAX)
AS
BEGIN
    -- Restore base64 padding
    DECLARE @pad_length INT = 4 - (LEN(@input) % 4)
    IF @pad_length = 4 SET @pad_length = 0
    SET @input = REPLACE(REPLACE(@input, '-', '+'), '_', '/') + REPLICATE('=', @pad_length)
    
    RETURN CAST('' AS XML).value('xs:base64Binary(sql:variable("@input"))', 'VARBINARY(MAX)')
END
GO

-- Create table for storing keys
CREATE TABLE jwt.Keys
(
    KeyId INT IDENTITY(1,1) PRIMARY KEY,
    KeyName VARCHAR(50) NOT NULL,
    KeyType VARCHAR(20) NOT NULL, -- 'Symmetric' or 'Asymmetric'
    KeyValue VARBINARY(MAX) NOT NULL,
    PublicKey VARBINARY(MAX) NULL,
    Created DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    IsActive BIT NOT NULL DEFAULT 1
)
GO

-- Function to create JWT using symmetric key
CREATE OR ALTER FUNCTION jwt.create_token_symmetric
(
    @username VARCHAR(100),
    @claims VARCHAR(1000),
    @secret_key VARCHAR(100)
)
RETURNS VARCHAR(MAX)
AS
BEGIN
    DECLARE @header VARCHAR(MAX)
    DECLARE @payload VARCHAR(MAX)
    DECLARE @signature VARBINARY(MAX)
    
    -- Create header
    SET @header = jwt.base64_encode(CAST('{"alg":"HS256","typ":"JWT"}' AS VARBINARY(MAX)))
    
    -- Create payload
    SET @payload = jwt.base64_encode(CAST(
        '{' +
        '"username":"' + @username + '",' +
        '"claims":"' + @claims + '",' +
        '"exp":' + CAST(DATEDIFF(SECOND, '1970-01-01', DATEADD(HOUR, 1, GETUTCDATE())) AS VARCHAR(20)) +
        '}'
        AS VARBINARY(MAX)))
    
    -- Create signature using HMACSHA256
    SET @signature = HMACSHA2_256(
        CAST(@header + '.' + @payload AS VARBINARY(MAX)),
        CAST(@secret_key AS VARBINARY(MAX))
    )
    
    -- Combine all parts
    RETURN @header + '.' + @payload + '.' + jwt.base64_encode(@signature)
END
GO

-- Function to validate JWT using symmetric key
CREATE OR ALTER FUNCTION jwt.is_valid_symmetric
(
    @token VARCHAR(MAX),
    @secret_key VARCHAR(100)
)
RETURNS BIT
AS
BEGIN
    DECLARE @parts TABLE (id INT IDENTITY(1,1), value VARCHAR(MAX))
    DECLARE @header VARCHAR(MAX)
    DECLARE @payload VARCHAR(MAX)
    DECLARE @signature VARCHAR(MAX)
    DECLARE @calculated_signature VARBINARY(MAX)
    DECLARE @exp BIGINT
    
    -- Split token
    INSERT INTO @parts
    SELECT value FROM STRING_SPLIT(@token, '.')
    
    IF (SELECT COUNT(*) FROM @parts) != 3
        RETURN 0
        
    SELECT 
        @header = value FROM @parts WHERE id = 1,
        @payload = value FROM @parts WHERE id = 2,
        @signature = value FROM @parts WHERE id = 3
    
    -- Verify signature
    SET @calculated_signature = HMACSHA2_256(
        CAST(@header + '.' + @payload AS VARBINARY(MAX)),
        CAST(@secret_key AS VARBINARY(MAX))
    )
    
    IF jwt.base64_encode(@calculated_signature) != @signature
        RETURN 0
        
    -- Check expiration
    SET @exp = CAST(JSON_VALUE(
        CAST(jwt.base64_decode(@payload) AS VARCHAR(MAX)),
        '$.exp'
    ) AS BIGINT)
    
    IF @exp < DATEDIFF(SECOND, '1970-01-01', GETUTCDATE())
        RETURN 0
        
    RETURN 1
END
GO

-- Function to create JWT using asymmetric key
CREATE OR ALTER FUNCTION jwt.create_token_asymmetric
(
    @username VARCHAR(100),
    @claims VARCHAR(1000),
    @key_id INT
)
RETURNS VARCHAR(MAX)
AS
BEGIN
    DECLARE @header VARCHAR(MAX)
    DECLARE @payload VARCHAR(MAX)
    DECLARE @signature VARBINARY(MAX)
    DECLARE @private_key VARBINARY(MAX)
    
    -- Get private key
    SELECT @private_key = KeyValue 
    FROM jwt.Keys 
    WHERE KeyId = @key_id AND KeyType = 'Asymmetric' AND IsActive = 1
    
    IF @private_key IS NULL
        RETURN NULL
    
    -- Create header
    SET @header = jwt.base64_encode(CAST('{"alg":"RS256","typ":"JWT"}' AS VARBINARY(MAX)))
    
    -- Create payload
    SET @payload = jwt.base64_encode(CAST(
        '{' +
        '"username":"' + @username + '",' +
        '"claims":"' + @claims + '",' +
        '"exp":' + CAST(DATEDIFF(SECOND, '1970-01-01', DATEADD(HOUR, 1, GETUTCDATE())) AS VARCHAR(20)) +
        '}'
        AS VARBINARY(MAX)))
    
    -- Create signature using RSA
    SET @signature = SIGN(
        @private_key,
        CAST(@header + '.' + @payload AS VARBINARY(MAX)),
        'SHA2_256'
    )
    
    -- Combine all parts
    RETURN @header + '.' + @payload + '.' + jwt.base64_encode(@signature)
END
GO

-- Function to validate JWT using asymmetric key
CREATE OR ALTER FUNCTION jwt.is_valid_asymmetric
(
    @token VARCHAR(MAX),
    @key_id INT
)
RETURNS BIT
AS
BEGIN
    DECLARE @parts TABLE (id INT IDENTITY(1,1), value VARCHAR(MAX))
    DECLARE @header VARCHAR(MAX)
    DECLARE @payload VARCHAR(MAX)
    DECLARE @signature VARBINARY(MAX)
    DECLARE @public_key VARBINARY(MAX)
    DECLARE @exp BIGINT
    
    -- Get public key
    SELECT @public_key = PublicKey 
    FROM jwt.Keys 
    WHERE KeyId = @key_id AND KeyType = 'Asymmetric' AND IsActive = 1
    
    IF @public_key IS NULL
        RETURN 0
    
    -- Split token
    INSERT INTO @parts
    SELECT value FROM STRING_SPLIT(@token, '.')
    
    IF (SELECT COUNT(*) FROM @parts) != 3
        RETURN 0
        
    SELECT 
        @header = value FROM @parts WHERE id = 1,
        @payload = value FROM @parts WHERE id = 2,
        @signature = jwt.base64_decode(value) FROM @parts WHERE id = 3
    
    -- Verify signature
    IF VERIFYSIGNATURE(
        @public_key,
        CAST(@header + '.' + @payload AS VARBINARY(MAX)),
        @signature,
        'SHA2_256'
    ) = 0
        RETURN 0
        
    -- Check expiration
    SET @exp = CAST(JSON_VALUE(
        CAST(jwt.base64_decode(@payload) AS VARCHAR(MAX)),
        '$.exp'
    ) AS BIGINT)
    
    IF @exp < DATEDIFF(SECOND, '1970-01-01', GETUTCDATE())
        RETURN 0
        
    RETURN 1
END
GO

-- Example stored procedure to manage keys
CREATE OR ALTER PROCEDURE jwt.manage_keys
    @action VARCHAR(20),
    @key_name VARCHAR(50) = NULL,
    @key_type VARCHAR(20) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    IF @action = 'CREATE_SYMMETRIC'
    BEGIN
        DECLARE @symmetric_key VARBINARY(MAX) = CRYPT_GEN_RANDOM(32)
        
        INSERT INTO jwt.Keys (KeyName, KeyType, KeyValue)
        VALUES (@key_name, 'Symmetric', @symmetric_key)
        
        SELECT KeyId, KeyName, KeyValue
        FROM jwt.Keys
        WHERE KeyId = SCOPE_IDENTITY()
    END
    
    IF @action = 'CREATE_ASYMMETRIC'
    BEGIN
        DECLARE @private_key VARBINARY(MAX)
        DECLARE @public_key VARBINARY(MAX)
        
        -- Generate key pair
        CREATE ASYMMETRIC KEY temp_key
        WITH ALGORITHM = RSA_2048
        
        -- Export keys
        SELECT 
            @private_key = AsymKey_Id,
            @public_key = PublicKey
        FROM sys.asymmetric_keys
        WHERE name = 'temp_key'
        
        -- Clean up temporary key
        DROP ASYMMETRIC KEY temp_key
        
        -- Store keys
        INSERT INTO jwt.Keys (KeyName, KeyType, KeyValue, PublicKey)
        VALUES (@key_name, 'Asymmetric', @private_key, @public_key)
        
        SELECT KeyId, KeyName
        FROM jwt.Keys
        WHERE KeyId = SCOPE_IDENTITY()
    END
END
GO
