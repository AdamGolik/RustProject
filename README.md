# 🦀 RustProject

## 🧩 Actix Web API with JWT Auth and SeaORM

A full-stack backend REST API built with [Actix Web](https://actix.rs/), using **JWT** for authentication, **SeaORM** for database interaction, and **dotenv** for environment configuration. This server supports user registration, login, account management, and CRUD operations for client entries.

---

## 🏗 Features

- ✅ User registration, login, and account management
- 🔐 JWT-based authentication middleware
- 📁 CRUD operations on "clients", scoped to the authenticated user
- 📦 SeaORM integration for async DB operations
- 🛠 Database migration support
- 🔍 Optional search & pagination on client listing
- 🧪 Clean and testable modular structure

---

## 📁 Project Structure

.
├── src
│ ├── controller # Handlers for user and client endpoints
│ ├── entity # SeaORM entity definitions
│ ├── middleware # Custom JWT middleware
│ ├── main.rs # App entry point
│ └── migration # SeaORM migrations
├── .env # Environment variables
├── Cargo.toml # Dependencies and metadata

---

## ⚙️ Setup Instructions

### 1. Clone and Navigate

```bash
git clone https://github.com/AdamGolik/RustProject
cd RustProject
```

## 🔑 API Overview

### Public Endpoints

| Method | Path        | Description       |
| ------ | ----------- | ----------------- |
| GET    | `/`         | Health check      |
| POST   | `/register` | Register new user |
| POST   | `/login`    | Login, get JWT    |

### Protected Endpoints (JWT Required)

#### User

| Method | Path            | Description        |
| ------ | --------------- | ------------------ |
| GET    | `/user/account` | View user settings |
| PUT    | `/user/account` | Update user info   |
| DELETE | `/user/account` | Delete account     |

#### Clients

| Method | Path                     | Description       |
| ------ | ------------------------ | ----------------- |
| POST   | `/clients/add`           | Add new client    |
| GET    | `/clients/`              | Get all clients   |
| GET    | `/clients/{client_uuid}` | Get single client |
| PUT    | `/clients/{client_uuid}` | Update client     |
| DELETE | `/clients/{client_uuid}` | Delete client     |

##### 🔍 Optional Query Parameters for `/clients/`:

| Parameter  | Example Value         | Description                            |
| ---------- | --------------------- | -------------------------------------- |
| `page`     | `5`                   | Page number (default: 1)               |
| `per_page` | `2`                   | Results per page (default: 10)         |
| `search`   | `adam`                | Search term (applied to client fields) |
| `from`     | `2024-01-01T00:00:00` | Start of date range (ISO 8601)         |
| `to`       | `2024-01-31T23:59:59` | End of date range (ISO 8601)           |

**Example Request:**
