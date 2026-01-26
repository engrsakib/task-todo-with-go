# 🚀 Busra News API — Go-based Backend Service

[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/) [![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/) [![Gin Gonic](https://img.shields.io/badge/Gin_Gonic-008080?style=for-the-badge&logo=go&logoColor=white)](https://gin-gonic.com/) [![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white)](https://jwt.io/) [![Swagger](https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black)](https://swagger.io/) [![Render](https://img.shields.io/badge/Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://render.com/)

---

## Project Overview

**Busra News API** is a modern, production-ready backend service implemented in Go (Golang). It provides the core features required by a news platform: user authentication, news post creation and management, and a comment system. The application uses MongoDB for data persistence and the Gin Gonic framework for a fast, minimal HTTP API. JWT is used for secure token-based authentication.

The codebase follows clean architecture principles, emphasizes robust error handling, and is organized modularly to make the service scalable and easy to maintain.

---

## Key Features

- **User Authentication**: Registration, login, OTP verification, password reset and change flows.  
- **Post Management**: Create, read, update, and soft-delete news posts. Supports post scheduling and status management.  
- **Commenting System**: Add comments and replies on posts.  
- **Admin Panel Features**: Extra management capabilities for admin users to manage users and content.  
- **API Documentation**: Auto-generated, interactive API documentation using Swagger UI.  
- **Clean Architecture**: Modular services designed for testability and maintainability.

---

## Live Links

- **Backend Server:** https://news-with-go.onrender.com/  
- **Swagger UI (API Docs):** https://news-with-go.onrender.com/swagger/index.html

---

## Local Setup (Quick Start)

Follow these steps to run the project locally.

### Prerequisites

Make sure the following are installed and configured on your machine:

- **Go (Golang)** — https://go.dev/doc/install  
- **MongoDB** — local installation or a MongoDB Atlas cluster (https://docs.mongodb.com/manual/installation/)  
- **Git** — https://git-scm.com/

### Steps

1. Clone the repository and navigate to the server directory:
    ```bash
    git clone https://github.com/engrsakib/news-with-go.git
    cd news-with-go/server/busra-news
    ```
    Make sure you are in the correct directory where `main.go` resides.

2. Install module dependencies:
    ```bash
    go mod tidy
    ```

3. Create a `.env` file in the project root (next to `main.go`) and set the required environment variables:
    ```env
    MONGO_URI="mongodb://localhost:27017/busra_news" # your MongoDB connection string
    JWT_SECRET="your_jwt_secret_key"                 # a strong secret key for signing tokens
    SENDER_EMAIL="your_email@example.com"            # for sending OTPs
    SENDER_PASSWORD="your_email_password"            # email password or app password
    ```

4. Generate Swagger documentation (run this when first setting up or after API changes):
    ```bash
    go install github.com/swaggo/swag/cmd/swag@latest   # install swag if not already installed
    swag init
    ```

5. Run the application:
    ```bash
    go run main.go
    ```
    The server will run by default at `http://localhost:8080`.

---

## Developer Profile

**Md. Nazmus Sakib** — Backend Engineer

I am a dedicated backend engineer focused on building scalable, efficient, and maintainable systems. I work across Go, Python, and Node.js to deliver robust backend solutions for modern web applications.

- GitHub: https://github.com/engrsakib  
- LinkedIn: (Insert your LinkedIn profile link)  
- Portfolio / Website: (Insert your portfolio or website link)

---