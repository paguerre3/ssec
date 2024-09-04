# ssec
Spring Security Compendium


---
Authentication and authorization are two fundamental concepts in software security, often used together but serving distinct purposes:

**1. Authentication** is the **process of verifying the identity of a user or system**. It answers the question, 
**"Who are you?"** The goal is to ensure that the person or system attempting to access resources is indeed who they claim to be.

Common authentication methods include:
- **Passwords**: The most basic form, where users enter a secret word or phrase.
- **Multi-Factor Authentication (MFA)**: Combines two or more authentication factors (e.g., something you know, something you have, something you are) to increase security.
- **Biometrics**: Uses physical characteristics like fingerprints, facial recognition, or retina scans.
- **OAuth/OpenID Connect**: Tokens are used to authenticate users in web applications and APIs.

**2. Authorization** occurs after authentication and **determines what an authenticated user or system is allowed to do**. It answers the question, **"What can you do?"** This step ensures that users have the appropriate permissions to access specific resources or perform certain actions.

Common approaches to authorization include:
- **Role-Based Access Control (RBAC)**: Users are assigned roles, and permissions are granted based on those roles.
- **Access Control Lists (ACLs)**: Permissions are tied to specific resources, with a list specifying who can access each resource.
- **OAuth Scopes**: Define what resources an authenticated token can access in web services.
- **Attribute-Based Access Control (ABAC)**: Policies are defined based on attributes of the user, resource, and environment (e.g., time of day).

***How They Work Together***
1. **Authentication** happens first to confirm the identity of the user.
2. Once authenticated, **authorization** kicks in to determine what resources the user has permission to access.

For example, in a web application:
- **Authentication** ensures the user logging in with a username and password is legitimate.
- **Authorization** checks whether the authenticated user has the rights to view or modify specific data within the application.

Both authentication and authorization are critical for ensuring the security and integrity of software systems.


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
```jwt
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
⚠️"your-256-bit-secret" --> using "jwt.io" actually you can paste the secret here for verifying! i.e. to avoid tempering.
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

When using JWTs (JSON Web Tokens) in a Spring-based server for authentication and authorization, the typical flow can be described as follows:

***User Authentication (Login)***:
- 1.a. **Client Request**: A client (e.g., a web app, mobile app) **sends** a POST request to the server’s `/login` or `/authenticate` endpoint with the **user's credentials (usually username and password)**.
- 2.a. **Server Verification**:
   - The Spring server receives the request and verifies the credentials against the user details stored in the database (or another user management service).
   - **If the credentials are valid, the server generates a JWT containing claims that identify the user and their roles or permissions**.
- 2.b. **JWT Creation**:
   - The server creates a JWT with:
      - **Header**: Specifies the signing algorithm (e.g., `HS256`).
      - **Payload**: Contains claims such as `sub` (subject, typically the username), `exp` (expiration time), and any custom claims (e.g., user roles).
      - **Signature**: The server **signs the token using a secret key or a private key**.
- 3.a. **Token Response**: The server sends the JWT back to the client, typically in the response body or as part of the response headers (e.g., `Authorization: Bearer <token>`).

***Subsequent Requests (Using JWT for Authorization)***:
- 4.a. **Client Request with JWT**:
   - For subsequent API requests, the client includes the JWT in the `Authorization` header: `Authorization: Bearer <token>`.
- 4.b. **Server Interception**:
   - The Spring server intercepts the request via a filter, typically a `JwtAuthenticationFilter` or similar.
- 4.c. **Token Validation**:
   - The filter extracts the JWT from the `Authorization` header and validates it.
   - Validation steps include:
      - Checking the token’s signature to ensure it hasn’t been tampered with.
      - Verifying the token’s expiration time (`exp` claim).
      - Ensuring the token was issued by a trusted source (`iss` claim).
      - Optionally verifying the audience (`aud` claim).
- 4.d. **Authentication Context**:
   - **If the token is valid, the server extracts user details (e.g., `sub`, `roles`)** from the token and sets the authentication context in Spring Security (`SecurityContextHolder`).
   - This context is used **to authorize access to secured endpoints based on roles or permissions**.
- 4.c. **Request Processing**:
   - The request is passed to the appropriate controller or handler method.
   - The server processes the request and returns the response to the client.

***Token Expiration and Refresh***:
- **Token Expiration**:
   - JWTs typically have an expiration time (`exp` claim). Once expired, the client cannot use the token to access protected resources.
- **Refresh Token** (Optional):
   - Some implementations use a separate refresh token mechanism.
   - The client can send a request to a `/refresh-token` endpoint with the refresh token.
   - If valid, the server issues a new JWT without requiring the user to log in again.

![JWT and secret](./img/1-jwt-secret-flow.png?raw=true)

***Workflow summary***:

In this flow, JWTs are used to securely manage user sessions without storing state on the server. The Spring server validates and processes each request based on the token provided by the client, ensuring secure and scalable authentication and authorization.

---
### Further samples and useful links
- ***Forked Repository***
   
   [Reactive Programing, JWT, MSA and OAuth](https://github.com/paguerre3/Spring-Boot-Tutorials)

- ***JWT Validations***:
   
   [JWT IO](https://jwt.io/) to decode, verify and generate JWTs online.