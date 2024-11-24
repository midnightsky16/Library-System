
# Library System API

This Library System API is a comprehensive application featuring full CRUD/A functionality (Create, Read, Update, Delete, and Archive) with enhanced security measures, including JWT (JSON Web Token) tokenization for secure authentication and data integrity. The token circulation is automated so that there's no need no manualy insert the token to authenticate when performing an operation.



## Features

- **JWT Authentication:** Secure access to the API with JSON Web Tokens.
- **Token Revocation:** Ensures tokens are valid for only one use, enhancing security.
- **CRUD/A (Create, Delete, Update, Delete and Archive) Operations:** User and Author-Book Management.
- **Error Handling:** Comprehensive error messages for better debugging and client understanding.



## Technology Used
- **PHP:** Serves as the core backend programming language, leveraging the Slim Framework for efficient development.
- **Slim Framework:** A lightweight and fast PHP framework ideal for building robust APIs.
- **Firebase JWT:** A library used for securely managing JSON Web Tokens (JWT) for authentication.
- **PSR-7:** Provides standardized HTTP message interfaces for consistent request and response handling.
  
---

## API Authentication and Token Management

The API leverages JWT (JSON Web Tokens) for secure authentication and session management. Below are the key aspects of its implementation:

### Session Token:

- Upon logging into the system, a session token is generated and stored in httpOnly cookies to ensure secure handling.
- The session remains active for one hour of inactivity. If the system is unused beyond this period, the session will automatically expire, logging the user out.
### Unique Tokens for CRUD/A Operations:

- A unique token is automatically generated for each `Create, Read, Update, Delete, or Archive (CRUD/A)` operation.
- Users are not required to manually input these tokens as the API handles their circulation automatically.

### Token Restrictions:

- Tokens that have already been used for an operation cannot be reused for subsequent CRUD/A actions, ensuring enhanced security and preventing token misuse.
