
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

### AS3. AUTHOR ADD BOOK

  - **Endpoint:** `/author/books/add`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint allows an authenticated author to add a new book. The author must provide a title and content for the book. The request must include a valid JWT (JSON Web Token) to identify the author. The system will verify the JWT, fetch the author's ID based on the username in the token, and then insert the new book into the database. If the book is successfully added, a success message is returned. If there are any issues, appropriate error messages are returned.

  - **JWT Token Required:** Yes (the request must contain a valid JWT token in the `Authorization` header)

  - **Sample Request (JSON):**
    ```json
    {
        "title": "My New Book",
        "content": "This is the content of the book."
    }
    ```

  - **Response:**
    - **On Success (Book Added)**  
      ```json
      {
        "status": "success",
        "message": "Book added successfully"
      }
      ```

    - **On Failure (Author Not Found)**  
      ```json
      {
        "status": "error",
        "message": "Author not found"
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
    - `Authorization`: `Bearer <JWT_TOKEN>`

---
### AS4. AUTHOR EDIT BOOK

  - **Endpoint:** `/author/books/edit/{bookid}`  
  - **Method:** `PUT`  
  - **Description:**  
    This endpoint allows an authenticated author to update an existing book's title and content. The author must be authenticated with a valid JWT token. The book's `bookid` must match an existing book owned by the logged-in author. If the book exists and belongs to the author, the book's title and content will be updated. If the author does not own the book, or the book does not exist, an error will be returned.

  - **JWT Token Required:** Yes (the request must contain a valid JWT token in the `Authorization` header)

  - **Parameters:**
    - `bookid`: The ID of the book that the author wants to edit (provided in the URL path).

  - **Sample Request (JSON):**
    ```json
    {
        "title": "Updated Book Title",
        "content": "Updated content for the book."
    }
    ```

  - **Response:**
    - **On Success (Book Updated)**  
      ```json
      {
        "status": "success",
        "message": "Book updated successfully"
      }
      ```

    - **On Failure (Author Not Found)**  
      ```json
      {
        "status": "error",
        "message": "Author not found"
      }
      ```

    - **On Failure (Book Not Found or Permission Denied)**  
      ```json
      {
        "status": "error",
        "message": "Book not found or you do not have permission to edit this book"
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
    - `Authorization`: `Bearer <JWT_TOKEN>`

---
### AS5. AUTHOR DELETE BOOK

  - **Endpoint:** `/author/books/delete/{bookid}`  
  - **Method:** `DELETE`  
  - **Description:**  
    This endpoint allows an authenticated author to delete a book that they own. The author must be authenticated with a valid JWT token. The book's `bookid` must match an existing book owned by the logged-in author. If the book exists and belongs to the author, it will be deleted. If the author does not own the book, or the book does not exist, an error will be returned.

  - **JWT Token Required:** Yes (the request must contain a valid JWT token in the `Authorization` header)

  - **Parameters:**
    - `bookid`: The ID of the book that the author wants to delete (provided in the URL path).

  - **Sample Request (JSON):**
    ```json
    {}
    ```

  - **Response:**
    - **On Success (Book Deleted)**  
      ```json
      {
        "status": "success",
        "message": "Book deleted successfully"
      }
      ```

    - **On Failure (Author Not Found)**  
      ```json
      {
        "status": "error",
        "message": "Author not found"
      }
      ```

    - **On Failure (Book Not Found or Permission Denied)**  
      ```json
      {
        "status": "error",
        "message": "Book not found or you do not have permission to delete this book"
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
    - `Authorization`: `Bearer <JWT_TOKEN>`

---

### AS6. AUTHOR LOGOUT

  - **Endpoint:** `/author/logout`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint allows an authenticated author to log out by clearing the authentication token (`auth_token`) stored in a cookie. Upon successful logout, the author is logged out, and the authentication token is removed from the browser's cookies.

    **Note:** If the user is not logged in (i.e., there is no valid JWT token in the request), they will not be able to perform any operations, including logging out.

  - **JWT Token Required:** Yes (The request must contain a valid JWT token in the `Authorization` header)

  - **Parameters:**  
    None (The logout operation is based solely on the JWT token passed in the request).

  - **Sample Request (JSON):**
    ```json
    {}
    ```

  - **Response:**
    - **On Success (Logout Successful)**  
      ```json
      {
        "status": "success",
        "message": "Logged out successfully"
      }
      ```

    **Headers:**
    - `Content-Type`: `application/json`
    - `Authorization`: `Bearer <JWT_TOKEN>` (This is included in the header to authenticate the request.)

    **Cookies:**
    - `auth_token`: The authentication token will be cleared in the response.

---

## User Side Endpoints

This documentation outlines the authentication mechanism for the user section of the application. The system utilizes JWT (JSON Web Tokens) and cookies to manage secure sessions for the users. The users need to be logged-in to view the available books in the library system.

### US1. USER REGISTRATION


  - **Endpoint:** `/user/register`  
  - **Method:** `POST`  
  - **Description:**  
    This endpoint allows a new user to register by providing a `username` and `password`. The system checks if the `username` is already taken. If not, the new user's details are added to the database, and their password is securely hashed using the SHA-256 algorithm. This endpoint does not require authentication, as it is for new users who want to register.

  - **Sample Request (JSON):**
    ```json
    {
        "username": "newuser123",
        "password": "newpassword123"
    }
    ```

  - **Response:**
    - **On Success (Registration Successful)**  
      ```json
      {
        "status": "success",
        "message": "Registration Successful",
        "token": "<JWT_TOKEN>"
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

### US2. USER VIEW BOOK LIST

  - **Endpoint:** `/books`  
  - **Method:** `GET`  
  - **Description:**  
    This endpoint allows a user to view the list of non-archived books along with their authors. It fetches only the books that are not archived (`archived = 0`) and includes the author's name in the response. The response also includes a new JWT token for the user, which is set in the `auth_token` cookie.


  - **Response:**
    - **On Success (Books Available)**  
      ```json
      [
        {
          "bookid": 1,
          "title": "Book Title 1",
          "author": "Author Name"
        },
        {
          "bookid": 2,
          "title": "Book Title 2",
          "author": "Author Name"
        }
      ]
      ```

    - **On Success (No Books Available)**  
      ```json
      {
        "status": "success",
        "message": "No Books Available"
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
  - `Set-Cookie`: `auth_token=<JWT_TOKEN>; Path=/; HttpOnly; SameSite=Strict;`

---

### US3. USER VIEW SPECIFIC BOOK

  - **Endpoint:** `/books/{bookid}`  
  - **Method:** `GET`  
  - **Description:**  
    This endpoint allows a user to view the details of a specific book by its `bookid`. The system retrieves the book's title, author, and content, ensuring that the book is not archived (`archived = 0`). The response also includes a new JWT token for the user, set in the `auth_token` cookie.

  - **Sample Request (JSON):**
    - `/books/2`  
    ```json
    {
    }
  - **Response:**
    - **On Success (Book Found)**  
      ```json
      {
        "title": "Book Title",
        "author": "Author Name",
        "content": "Book content here..."
      }
      ```

    - **On Failure (Book Not Found or Archived)**  
      ```json
      {
        "status": "error",
        "message": "Book not found or has been archived."
      }
      ```
    - **On Failure (User not logged-in. Token or Session Expired)**  
      ```json
      {
        "status": "failed",
        "message": "Unauthorized: Expired token"
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
  - `Set-Cookie`: `auth_token=<JWT_TOKEN>; Path=/; HttpOnly; SameSite=Strict;`

