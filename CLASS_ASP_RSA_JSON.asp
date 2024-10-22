<%
Class JWT
    Private m_Secret
    Private m_PublicKey
    Private m_PrivateKey
    
    Private Sub Class_Initialize()
        m_Secret = "your-secret-key-here"
    End Sub
    
    Public Property Let Secret(value)
        m_Secret = value
    End Property
    
    Public Property Let PublicKey(value)
        m_PublicKey = value
    End Property
    
    Public Property Let PrivateKey(value)
        m_PrivateKey = value
    End Property
    
    ' Helper function to encode base64
    Private Function Base64Encode(bytes)
        Dim dom, el
        Set dom = CreateObject("Microsoft.XMLDOM")
        Set el = dom.createElement("tmp")
        el.dataType = "bin.base64"
        el.nodeTypedValue = bytes
        Base64Encode = Replace(Replace(el.text, vbLf, ""), "=", "")
        Set el = Nothing
        Set dom = Nothing
    End Function
    
    ' Helper function to decode base64
    Private Function Base64Decode(b64String)
        Dim dom, el
        Set dom = CreateObject("Microsoft.XMLDOM")
        Set el = dom.createElement("tmp")
        el.dataType = "bin.base64"
        el.text = b64String
        Base64Decode = el.nodeTypedValue
        Set el = Nothing
        Set dom = Nothing
    End Function
    
    ' Create JWT using symmetric key
    Public Function CreateToken(username, claims)
        Dim header, payload, signature
        Dim crypto
        Set crypto = CreateObject("System.Security.Cryptography.HMACSHA256")
        
        ' Create header
        header = "{""alg"":""HS256"",""typ"":""JWT""}"
        
        ' Create payload
        payload = "{""username"":""" & username & """,""claims"":""" & claims & """,""exp"":" & _
                 DateDiff("s", "1/1/1970", DateAdd("h", 1, Now())) & "}"
        
        ' Encode header and payload
        header = Base64Encode(StringToBytes(header))
        payload = Base64Encode(StringToBytes(payload))
        
        ' Create signature
        crypto.Key = StringToBytes(m_Secret)
        signature = Base64Encode(crypto.ComputeHash_2(StringToBytes(header & "." & payload)))
        
        CreateToken = header & "." & payload & "." & signature
        Set crypto = Nothing
    End Function
    
    ' Create JWT using RSA
    Public Function CreateTokenRSA(username, claims)
        Dim header, payload, signature
        Dim rsa
        Set rsa = CreateObject("System.Security.Cryptography.RSACryptoServiceProvider")
        
        ' Load private key
        rsa.FromXmlString m_PrivateKey
        
        ' Create header
        header = "{""alg"":""RS256"",""typ"":""JWT""}"
        
        ' Create payload
        payload = "{""username"":""" & username & """,""claims"":""" & claims & """,""exp"":" & _
                 DateDiff("s", "1/1/1970", DateAdd("h", 1, Now())) & "}"
        
        ' Encode header and payload
        header = Base64Encode(StringToBytes(header))
        payload = Base64Encode(StringToBytes(payload))
        
        ' Create signature
        signature = Base64Encode(rsa.SignData(StringToBytes(header & "." & payload), "SHA256"))
        
        CreateTokenRSA = header & "." & payload & "." & signature
        Set rsa = Nothing
    End Function
    
    ' Validate JWT using symmetric key
    Public Function IsValid(token)
        Dim parts, header, payload, signature, calculatedSignature
        Dim crypto
        
        parts = Split(token, ".")
        If UBound(parts) <> 2 Then
            IsValid = False
            Exit Function
        End If
        
        header = parts(0)
        payload = parts(1)
        signature = parts(2)
        
        ' Verify signature
        Set crypto = CreateObject("System.Security.Cryptography.HMACSHA256")
        crypto.Key = StringToBytes(m_Secret)
        calculatedSignature = Base64Encode(crypto.ComputeHash_2(StringToBytes(header & "." & payload)))
        
        If signature <> calculatedSignature Then
            IsValid = False
            Exit Function
        End If
        
        ' Check expiration
        Dim decodedPayload, exp
        decodedPayload = BytesToString(Base64Decode(payload))
        exp = CLng(GetJsonValue(decodedPayload, "exp"))
        
        IsValid = (exp > DateDiff("s", "1/1/1970", Now()))
        Set crypto = Nothing
    End Function
    
    ' Validate JWT using RSA
    Public Function IsValidRSA(token)
        Dim parts, header, payload, signature
        Dim rsa
        
        parts = Split(token, ".")
        If UBound(parts) <> 2 Then
            IsValidRSA = False
            Exit Function
        End If
        
        header = parts(0)
        payload = parts(1)
        signature = Base64Decode(parts(2))
        
        ' Verify signature
        Set rsa = CreateObject("System.Security.Cryptography.RSACryptoServiceProvider")
        rsa.FromXmlString m_PublicKey
        
        If Not rsa.VerifyData(StringToBytes(header & "." & payload), signature, "SHA256") Then
            IsValidRSA = False
            Exit Function
        End If
        
        ' Check expiration
        Dim decodedPayload, exp
        decodedPayload = BytesToString(Base64Decode(payload))
        exp = CLng(GetJsonValue(decodedPayload, "exp"))
        
        IsValidRSA = (exp > DateDiff("s", "1/1/1970", Now()))
        Set rsa = Nothing
    End Function
    
    ' Helper functions for string/byte conversion
    Private Function StringToBytes(str)
        Dim stream
        Set stream = CreateObject("ADODB.Stream")
        stream.Type = 2 'adTypeText
        stream.Charset = "UTF-8"
        stream.Open
        stream.WriteText str
        stream.Position = 0
        stream.Type = 1 'adTypeBinary
        StringToBytes = stream.Read
        stream.Close
        Set stream = Nothing
    End Function
    
    Private Function BytesToString(bytes)
        Dim stream
        Set stream = CreateObject("ADODB.Stream")
        stream.Type = 1 'adTypeBinary
        stream.Open
        stream.Write bytes
        stream.Position = 0
        stream.Type = 2 'adTypeText
        stream.Charset = "UTF-8"
        BytesToString = stream.ReadText
        stream.Close
        Set stream = Nothing
    End Function
    
    ' Helper function to extract values from JSON
    Private Function GetJsonValue(json, key)
        Dim re, matches
        Set re = New RegExp
        re.Pattern = """" & key & """:""?([^"",}]+)""?"
        re.Global = False
        Set matches = re.Execute(json)
        If matches.Count > 0 Then
            GetJsonValue = matches(0).SubMatches(0)
        Else
            GetJsonValue = ""
        End If
        Set re = Nothing
    End Function
End Class

' Usage example:
Dim jwt
Set jwt = New JWT

' Symmetric key example
Dim token
token = jwt.CreateToken("john.doe", "admin,user")
Response.Write "Token is valid: " & jwt.IsValid(token) & vbCrLf

' Asymmetric key example
jwt.PrivateKey = "... your private key in XML format ..."
jwt.PublicKey = "... your public key in XML format ..."
token = jwt.CreateTokenRSA("john.doe", "admin,user")
Response.Write "RSA Token is valid: " & jwt.IsValidRSA(token)
%>
