
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


# JWT Middleware for User and Author Side

This `middleware` ensures secure authentication by validating JWT tokens stored in **httpOnly cookies**. If a valid token is present, the request is authorized, and a new token is generated to maintain session continuity. Below is the implementation:

## User and Author Middleware Function

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
# JWT Middleware for Admin Side

This document provides an overview of the middleware function designed to handle JWT (JSON Web Token) authentication for the Admin side of an application. The middleware checks if the JWT token is present in the `httpOnly` cookies and verifies it for authorized access. If valid, it generates a new token and refreshes the `admin_auth_token` cookie for the next request.

## Admin Middleware Function

```php
// Middleware to check JWT token stored in httpOnly cookies for Admin
$adminJwtMiddleware = function (Request $request, Response $response, $next) {
    $cookies = $request->getCookieParams();
    $token = $cookies['admin_auth_token'] ?? '';

    if ($token) {
        try {
            // Decode the token with the secret key
            $decoded = JWT::decode($token, new Key($GLOBALS['key'], 'HS256'));
            $request = $request->withAttribute('jwt', $decoded);

            // Proceed with the request
            $response = $next($request, $response);

            // After the action, generate a new token and set the cookie
            $username = $decoded->data->username;
            $newToken = createJWT($username, $GLOBALS['key']); // Same helper function
            $cookie = 'admin_auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';

            return $response->withHeader('Set-Cookie', $cookie);
        } catch (Exception $e) {
            // Handle invalid or expired token error
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Unauthorized: " . $e->getMessage()]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } else {
        // Handle missing token error
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


This documentation outlines the authentication mechanism for the admin section of the application. The system utilizes JWT (JSON Web Tokens) and cookies to manage secure sessions for the admin user. It consists of an endpoint for logging in as an admin and a middleware for validating JWT tokens.

## A1. ADMIN LOGIN ENDPOINT

  - **Endpoint:** `/admin/login`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint is used for authenticating the admin user by validating the provided username and password. If the credentials are correct, a JSON Web Token (JWT) is generated and stored in an `httpOnly` cookie for future secure requests. This token ensures that the admin remains authenticated across sessions.
  
  - **Sample Request (JSON):**
    ```json
    {
      "username": "adminls",
      "password": "cit@adminls"
    }
    ```
  
  - **Response:**
    - **On Success (Admin Login Successful)**
      ```json
      {
        "status": "success",
        "message": "Admin login successful"
      }
      ```
      **Headers:**
      - `Set-Cookie`: `admin_auth_token=<JWT_TOKEN>; Path=/; HttpOnly; SameSite=Strict;`
      - `Content-Type`: `application/json`
      
    - **On Failure (Authentication Failed)**
      ```json
      {
        "status": "failed",
        "message": "Authentication failed"
      }
      ```
      **Headers:**
      - `Content-Type`: `application/json`
      
---
### A2. ADMIN ARCHIVING AND UNARCHIVING BOOKS

  - **Endpoint:** `/admin/books/toggleArchive/{bookid}`  
  - **Method:** `PUT`  
  - **Description:**  
    This endpoint allows the admin to archive or unarchive a book by updating its `archived` status in the database. The `archive` status is passed as a boolean in the request body (`true` for archiving, `false` for unarchiving). Once the operation is performed, a new JWT token is generated for the admin, and the updated token is stored in an `httpOnly` cookie for secure session handling.

    - **True (archive):** Archives the book, setting the `archived` field to `true`.
    - **False (unarchive):** Unarchives the book, setting the `archived` field to `false`.

  - **Sample Request (JSON):**
    ```json
    {
      "archive": true
    }
    ```

  - **Response:**
    - **On Success (Book Archive Status Updated)**
      ```json
      {
        "status": "success",
        "message": "Book archive status updated"
      }
      ```
      **Headers:**
      - `Set-Cookie`: `admin_auth_token=<NEW_JWT_TOKEN>; Path=/; HttpOnly; SameSite=Strict;`
      - `Content-Type`: `application/json`

    - **On Failure (Database Error or Other Issues)**
      ```json
      {
        "status": "error",
        "message": "<ERROR_MESSAGE>"
      }
      ```
      **Headers:**
      - `Content-Type`: `application/json`

---

### Example: Admin Archiving a Book

#### Request:
```bash
PUT /admin/books/toggleArchive/12345
Content-Type: application/json

{
  "archive": true
}
```
---

### A3. ENABLING AND DISABLING OF ACCOUNTS

  - **Endpoint:** `/admin/users/toggle/{userid}`  
  - **Method:** `PUT`  
  - **Description:**  
    This endpoint allows the admin to enable or disable a user account. The current status of the user account is checked, and if the account is currently "enabled," it will be disabled, and vice versa. Once the status is toggled, the updated status is reflected in the database. The admin is required to be authenticated via the `adminJwtMiddleware` before performing this action.

  - **Sample Request (JSON):**
    No request body is required for this operation, as the system will automatically toggle the user status.

  - **Response:**
    - **On Success (User Status Updated)**  
      ```json
      {
        "status": "success",
        "message": "User status updated"
      }
      ```

    - **On Failure (Database Error or Other Issues)**  
      ```json
      {
        "status": "error",
        "message": "<ERROR_MESSAGE>"
      }
      ```
      **Headers:**
      - `Content-Type`: `application/json`

---

### Example: Enabling or Disabling a User Account

#### Request:
```bash
PUT /admin/users/toggle/12345
```
### A4. ADMIN LOGOUT ENDPOINT

The `/admin/logout` endpoint is responsible for securely logging out an admin user by performing the following:

1. **Token Removal**: Clears the `admin_auth_token` cookie by setting it with an expired timestamp.
2. **Response**: Returns a JSON response indicating successful logout.
3. **Security**: Ensures that the `HttpOnly` and `SameSite=Strict` attributes are applied to the cookie to prevent security vulnerabilities.

### Route Implementation

```php
$app->post('/admin/logout', function (Request $request, Response $response, array $args) {
    $cookie = 'admin_auth_token=; Path=/; HttpOnly; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    $response->getBody()->write(json_encode(["status" => "success", "message" => "Logged out successfully"]));
    return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
});
```
---

## Author Side Endpoints

This documentation outlines the authentication mechanism for the author section of the application. The system utilizes JWT (JSON Web Tokens) and cookies to manage secure sessions for the authors. It consists of an endpoint for logging in as an author and a middleware for validating JWT tokens.

### AS1. AUTHOR REGISTRATION


  - **Endpoint:** `/author/register`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint allows a new author to register by providing their name, a unique username, and a password. The system checks if the username is already taken. If not, the new author’s details are added to the database, and their password is securely hashed using the SHA-256 algorithm. This endpoint does not require authentication, as it is for new users who want to register.

  - **Sample Request (JSON):**
    ```json
    {
        "name": "John Doe",
        "username": "johndoe",
        "password": "securepassword123"
    }
    ```

  - **Response:**
    - **On Success (Registration Successful)**  
      ```json
      {
        "status": "success",
        "message": "Author registration successful"
      }
      ```

    - **On Failure (Username Already Taken)**  
      ```json
      {
        "status": "error",
        "message": "Username already taken"
      }
      ```

    - **On Failure (Database Error)**  
      ```json
      {
        "status": "error",
        "message": "<ERROR_MESSAGE>"
      }
      ```
      **Headers:**
      - `Content-Type`: `application/json`

---

### AS2. AUTHOR LOGIN

  - **Endpoint:** `/author/login`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint allows an existing author to log in by providing their username and password. The system verifies the credentials, and if they are correct, it generates a JWT (JSON Web Token) that is sent as a cookie to the client for session management. The client must use this token for subsequent requests that require authentication. If the credentials are incorrect, the request is denied with a 401 status.

  - **Sample Request (JSON):**
    ```json
    {
        "username": "johndoe",
        "password": "securepassword123"
    }
    ```

  - **Response:**
    - **On Success (Login Successful)**  
      ```json
      {
        "status": "success",
        "message": "Login successful"
      }
      ```

    - **On Failure (Authentication Failed)**  
      ```json
      {
        "status": "failed",
        "message": "Authentication failed"
      }
      ```

    - **On Failure (Database Error)**  
      ```json
      {
        "status": "failed",
        "message": "<ERROR_MESSAGE>"
      }
      ```
      **Headers:**
      - `Content-Type`: `application/json`
      - `Set-Cookie`: `auth_token=<JWT_TOKEN>; Path=/; HttpOnly; SameSite=Strict;`

---





