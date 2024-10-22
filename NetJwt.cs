using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth
{
    public class JwtService
    {
        private readonly string _symmetricKey;
        private readonly RsaSecurityKey _rsaKey;
        
        public JwtService(string symmetricKey = null, string rsaPrivateKey = null, string rsaPublicKey = null)
        {
            _symmetricKey = symmetricKey;
            
            if (!string.IsNullOrEmpty(rsaPrivateKey) || !string.IsNullOrEmpty(rsaPublicKey))
            {
                var rsa = RSA.Create();
                if (!string.IsNullOrEmpty(rsaPrivateKey))
                    rsa.ImportFromPem(rsaPrivateKey);
                else
                    rsa.ImportFromPem(rsaPublicKey);
                
                _rsaKey = new RsaSecurityKey(rsa);
            }
        }
        
        public string CreateTokenSymmetric(string username, string claims, TimeSpan? expiration = null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_symmetricKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            
            return CreateToken(username, claims, credentials, expiration);
        }
        
        public string CreateTokenAsymmetric(string username, string claims, TimeSpan? expiration = null)
        {
            var credentials = new SigningCredentials(_rsaKey, SecurityAlgorithms.RsaSha256);
            return CreateToken(username, claims, credentials, expiration);
        }
        
        private string CreateToken(string username, string claims, SigningCredentials credentials, TimeSpan? expiration)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var now = DateTime.UtcNow;
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim("claims", claims)
                }),
                
                Expires = now.Add(expiration ?? TimeSpan.FromHours(1)),
                SigningCredentials = credentials
            };
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        
        public bool ValidateTokenSymmetric(string token, out TokenValidationResult result)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_symmetricKey));
            return ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out result);
        }
        
        public bool ValidateTokenAsymmetric(string token, out TokenValidationResult result)
        {
            return ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _rsaKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out result);
        }
        
        private bool ValidateToken(string token, TokenValidationParameters parameters, out TokenValidationResult result)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                result = tokenHandler.ValidateToken(token, parameters);
                return true;
            }
            catch (Exception)
            {
                result = new TokenValidationResult { IsValid = false };
                return false;
            }
        }
        
        public class TokenValidationResult
        {
            public bool IsValid { get; set; }
            public string Username { get; set; }
            public string Claims { get; set; }
            public DateTime? Expiration { get; set; }
            
            public static implicit operator TokenValidationResult(TokenValidationResult validationResult)
            {
                if (validationResult == null || !validationResult.IsValid)
                    return new TokenValidationResult { IsValid = false };
                
                var token = validationResult as JwtSecurityToken;
                return new TokenValidationResult
                {
                    IsValid = true,
                    Username = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value,
                    Claims = token.Claims.FirstOrDefault(c => c.Type == "claims")?.Value,
                    Expiration = token.ValidTo
                };
            }
        }
    }
    
    // Example usage
    // Symmetric key example
    //          var symmetricService = new JwtService(symmetricKey: "your-secret-key-here");
    //        var symmetricToken = symmetricService.CreateTokenSymmetric("john.doe", "admin,user");

  
