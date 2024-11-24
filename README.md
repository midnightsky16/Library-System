
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

---


# Middleware for User and Author Side

This `middleware` ensures secure authentication by validating JWT tokens stored in **httpOnly cookies**. If a valid token is present, the request is authorized, and a new token is generated to maintain session continuity. Below is the implementation:

## Middleware Implementation

```php
// Middleware to check JWT token stored in httpOnly cookies
$jwtMiddleware = function (Request $request, Response $response, $next) {
    $cookies = $request->getCookieParams();
    $token = $cookies['auth_token'] ?? '';

    if ($token) {
        try {
            $decoded = JWT::decode($token, new Key($GLOBALS['key'], 'HS256'));
            $request = $request->withAttribute('jwt', $decoded);
            
            // Proceed with the request
            $response = $next($request, $response);

            // After the action, generate a new token and set the cookie
            $username = $decoded->data->username;
            $newToken = createJWT($username, $GLOBALS['key']);
            $cookie = 'auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';
            
            return $response->withHeader('Set-Cookie', $cookie);
        } catch (Exception $e) {
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Unauthorized: " . $e->getMessage()]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } else {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => "Token not provided"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
};

```
## Helper Function: Generate JWT Token

The `createJWT` function is a utility to generate secure JSON Web Tokens (JWT) for authentication and session management. Below is a detailed explanation of its parameters, structure, and purpose.

### Function Definition

```php
// Helper function to create JWT token
function createJWT($username, $key) {
    $expire = time();
    $payload = [
        'iss' => 'http://cit.dmmmsu.gov.ph', // Issuer of the token
        'aud' => 'http://cit.elibrary.gov.ph', // Audience for whom the token is intended
        'iat' => $expire,                     // Issued at timestamp
        'exp' => $expire + (60 * 60),         // Expiration timestamp (1 hour)
        'data' => [
            'username' => $username           // Payload data containing the username
        ]
    ];
    return JWT::encode($payload, $key, 'HS256'); // Encodes the payload using the secret key and HS256 algorithm
}
```



# CREATE, READ, UPDATE, DELETE AND ARCHIVE (CRUD/A) OPERATIONS

## Admin Side Endpoints

### A1. USER AUTHENTICATE
  - **Endpoint:** `/user/authenticate`  
  - **Method:** `POST`  
  - **Description:** 
    Validates user credentials by checking the provided username and password against the database. If authentication is successful, a JSON Web Token (JWT) is generated and returned for secure session handling.  - **Sample Request(JSON):**
      ```json
          {
            "username": "janedoe",
            "password": "securepassword123"
          }
      ```
  - **Response:**
      - **On Success**
          ```json
              {
                  "status": "success",
                  "token": "<TOKEN>",
                  "data": null
              }
          ```
      - **On Failure (Authenthication Failed):**
          ```json
              {
                  "status": "fail",
                  "data": {
                      "title": "Authentication Failed!"
                  }
              }
          ```
---
