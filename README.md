#  Secure API Gateway (FastAPI)

A secure RESTful Notes API built with **FastAPI**, implementing JWT authentication, SQLAlchemy ORM, and a custom middleware-based security layer for threat detection and rate limiting.

This project demonstrates backend architecture design, authentication flow, and application-level security controls.

---

##  Features

- User Registration & Login
- JWT Authentication (OAuth2 Password Flow)
- Create / Read / Delete Notes (Authenticated)
- Regex-based SQL Injection Detection
- Regex-based XSS Detection
- IP-based Rate Limiting
- Security Event Logging
- Layered and modular project structure

---

##  Tech Stack

- FastAPI  
- SQLAlchemy  
- Pydantic  
- SQLite  
- python-jose (JWT)  
- Passlib (bcrypt)  
- Starlette Middleware  

---

##  Project Structure

```

app/
│
├── main.py
├── database.py
├── models.py
├── schemas.py
├── auth.py
│
├── middleware/
│   └── threat_detector.py
│
└── routers/
    ├── auth.py
    └── notes.py

```

---

##  Security Features overview

###  JWT Authentication
- Tokens include expiration time
- Uses HS256 algorithm
- Secure password hashing via bcrypt

###  SQL Injection & XSS Detection
Middleware scans:
- Query parameters
- Request body

If malicious patterns are detected:
- Request is blocked
- Threat is logged in database

###  Rate Limiting
- 10 requests per 60 seconds per IP
- Prevents brute force & abuse
- Violations logged

###  Security Logging
Blocked requests are stored with:
- IP address
- Threat type
- Request path
- Payload snapshot
- Timestamp

---

##  Installation & Setup

###  Clone the Repository

```

git clone <my-repo-url>
cd secure-api-gateway

```

###  Create Virtual Environment

```

python -m venv venv

```

Activate it:

**Windows**
```

venv\Scripts\activate

```

###  Install Dependencies

```

pip install -r requirements.txt

```

---

##  Environment Variables

Create a `.env` file in the project root:

```

SECRET_KEY=my_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./app.db

```

---

##  Running the Application

```

uvicorn app.main:app --reload

```

Server will run at:

```

[http://127.0.0.1:8000](http://127.0.0.1:8000)

```

Interactive API documentation:

```

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

````

---

##  API Endpoints

---

###  Authentication

#### POST `/auth/register`

**Request**
```json
{
  "username": "john",
  "password": "password123"
}
````

**Response**

```json
{
  "message": "User created successfully"
}
```

---

#### POST `/auth/login`

**Request**

```json
{
  "username": "john",
  "password": "password123"
}
```

**Response**

```json
{
  "access_token": "your_jwt_token_here",
  "token_type": "bearer"
}
```

---

###  Notes (Protected Routes)

All note endpoints require:

```
Authorization: Bearer <your_access_token>
```

---

#### POST `/notes/`

**Request**

```json
{
  "title": "My First Note",
  "content": "This is secure."
}
```

**Response**

```json
{
  "id": 1,
  "title": "My First Note",
  "content": "This is secure.",
  "owner_id": 1
}
```

---

#### GET `/notes/`

**Response**

```json
[
  {
    "id": 1,
    "title": "My First Note",
    "content": "This is secure.",
    "owner_id": 1
  }
]
```

---

#### DELETE `/notes/{note_id}`

**Response**

```json
{
  "message": "Note deleted successfully"
}
```

---

##  Regex-Based Threat Detector (Explanation)

The application uses a custom middleware (`ThreatDetectionMiddleware`) to intercept every incoming request before it reaches the route handlers.

### How It Works

1. The middleware executes before authentication and routing logic.
2. It extracts:

   * Client IP address
   * Query parameters
   * Request body (for POST, PUT, PATCH requests)
3. Each input is scanned using predefined regular expression (regex) patterns.
4. Pattern matching is performed using:

```python
re.search(pattern, text, re.IGNORECASE)
```

* `re.search()` checks whether any part of the input matches a suspicious pattern.
* `re.IGNORECASE` ensures detection regardless of capitalization.

### SQL Injection Patterns Detected

Examples:

* `OR 1=1`
* `UNION SELECT`
* `; DROP TABLE`
* `--` (SQL comment injection)

### XSS Patterns Detected

Examples:

* `<script>`
* `javascript:`
* `onerror=`
* `<iframe>`

### If a Threat is Detected

* The request is immediately blocked
* A security log entry is created in the database
* A safe HTTP error response is returned
* The route logic is never executed

This provides a basic application-layer defense against common injection attacks.

---

##  Rate Limiting

* 10 requests per 60 seconds per IP
* Implemented using in-memory request tracking
* Excess requests return HTTP 429 (Too Many Requests)
* Violations are logged

---

##  Architecture Overview

```
Client Request
        ↓
Threat Detection Middleware
        ↓
JWT Validation (Dependency Injection)
        ↓
Router
        ↓
SQLAlchemy ORM
        ↓
Database
```

---

##  Limitations

* In-memory rate limiting (not distributed)
* SQLite intended for development
* Regex-based detection provides basic protection only

---


##  Author

Built as part of a backend engineering assessment task.

```

---


