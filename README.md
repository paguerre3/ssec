# ssec
Spring Security Compendium


---
### JWT (JSON Web Token)
**JWTs** are **an open, industry standard RFC 7519 method for representing claims securely between two parties**. 
It is **commonly used for authentication and authorization in web applications**.

***Key Concepts***:

1. **Structure**:
    - A JWT is divided into three parts, separated by dots (`.`):
        1. **Header**: Contains metadata about the type of token and *the signing algorithm*.
        2. **Payload**: Contains the claims or statements about an entity (*typically, the user and its perms*) and additional data. This part is base64-encoded.
        3. **Signature**: Used to verify the token's integrity and authenticity. It's created by combining the encoded header, payload, and a *secret or private key*, then signing the result with a specified algorithm.

   Example JWT: `header.payload.signature`

2. **Usage**:
    - **Authentication**: After a user successfully logs in, a JWT is generated and sent to the client (usually in the response header). 
   The client stores the token (typically in local storage or a cookie) and sends it in subsequent requests to access protected resources.
    - **Authorization**: The server verifies the token's signature to ensure it has NOT been tampered with, 
   then extracts the user's identity and permissions from the payload to authorize access.

3. **Claims**:
*Claims are statements about an entity (typically the user and perms) and additional data*. 
These claims are *embedded in the payload section* of the JWT and are used to convey information between parties securely, e.g.
    - **Registered Claims**: Predefined claims like `iss` (issuer), `exp` (expiration time), `sub` (subject), and `aud` (audience).
    - **Public Claims**: Claims that can be defined by anyone, but they should be *registered in the IANA JSON Web Tokens Registry* to avoid collisions, e.g. `username` and `email`.
    - **Private Claims**: Custom claims created to share information between parties that agree on using them, e.g. `role` and `department`.

*Encoded JWT sample*:
```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
*Decoded JWT*:
Header (ALGORITHM & TOKEN TYPE):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
Payload (DATA):
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
Verify Signature:
```text
HMACSHA256(
base64UrlEncode(header) + "." +
base64UrlEncode(payload),
your-256-bit-secret
)
```

***Benefits***:
- **Stateless**: Since JWTs are self-contained, the server doesn’t need to store session data, making it scalable.
- **Compact**: The token is URL-safe and easy to pass around in HTTP headers.
- **Versatile**: JWTs can be used across different environments (web, mobile, IoT).

***Security Considerations***:
- **Signing**: Ensure the token is signed with a strong secret or private key using algorithms like `HS256` or `RS256`.
- **Expiration**: Set appropriate expiration times to limit the token's validity period.
- **HTTPS**: Always transmit JWTs over HTTPS to prevent interception.

JWTs are widely used in modern web applications for secure and efficient authentication and authorization.


---
### How JWT works in Spring
![How JWT works](./img/0-jwt-flow.png?raw=true)


---
### Further samples and useful links
- ***Forked Repository***

[Reactive Programing, JWT, MSA and OAuth](https://github.com/paguerre3/Spring-Boot-Tutorials)

- ***JWT Validations***:

[JWT IO](https://jwt.io/) to decode, verify and generate JWTs online.