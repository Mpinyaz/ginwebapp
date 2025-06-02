# Go Web Application

A modular and scalable web application built with **Go**, using the [Gin](https://github.com/gin-gonic/gin) web framework and [Templ](https://templ.guide) for HTML templating. The architecture emphasizes separation of concerns, maintainability, and clean organization of application logic.

## Features

- **User Authentication**
  - Register, login, logout
  - Secure password hashing
  - Session/cookie-based auth
- **Form Validation**
  - DTO-based validation
  - Persistent input handling with contextual errors
- **Component-Based UI**
  - Built using Templ (Go template engine)
  - Modular views and shared layout system
- **Database Integration**
  - GORM ORM for PostgreSQL or other relational DBs
  - Abstracted repositories for clean data access
- **Tailwind CSS**
  - Utility-first styling via Node.js build pipeline
  - Structured in `src/` and compiled to `output/`
- **Middleware and Caching**
  - Custom middleware (auth/user context)
  - Caching utilities (Redis-ready)

## Project Structure

```

.
├── cmd
│   └── main.go                      # Application entry point; bootstraps the server
├── config
│   └── config.go                    # Configuration loading (e.g., env vars, app settings)
├── db
│   └── db.go                        # Database connection setup (could be legacy or low-level)
├── internal                        # Internal application modules (encapsulation for domain logic)
│   ├── auth
│   │   └── auth.go                  # Authentication logic (tokens, sessions, etc.)
│   ├── cache
│   │   └── cache.go                 # Caching utilities (e.g., Redis wrappers)
│   ├── dtos
│   │   └── users_dto.go             # Data Transfer Objects (DTOs) for user input/output
│   ├── handlers                    # HTTP handlers / controllers
│   │   ├── auth.handlers.go         # Auth-related endpoints (login, register, logout)
│   │   ├── user.handlers.go         # User-specific endpoints (profile, settings)
│   │   └── view.handlers.go         # Public or template-rendered pages (e.g., homepage)
│   ├── middleware
│   │   └── user.go                  # Middleware for user context, auth checks, etc.
│   ├── models
│   │   └── users
│   │       └── users.go             # GORM models or schema for User
│   ├── repositories
│   │   └── user.go                  # Data access layer for users (DB operations abstracted)
│   ├── routes
│   │   ├── auth.routes.go           # Defines auth-related routes
│   │   ├── user.routes.go           # Defines user-related routes
│   │   └── view.routes.go           # Defines routes for view rendering (pages)
│   ├── store
│   │   └── db.go                    # Shared DB store or transactional logic
│   ├── utils
│   │   └── utils.go                 # Utility functions (e.g., hashing, validators, helpers)
│   └── views                       # View components using Go templates (e.g., Templ)
│       ├── components
│       │   ├── navbar.templ         # Templ file for navbar component
│       │   ├── navbar_templ.go      # Generated Go file from navbar.templ
│       │   ├── registerform.templ   # Templ file for registration form
│       │   └── registerform_templ.go# Generated Go file from registerform.templ
│       ├── layouts
│       │   ├── base.templ           # Base HTML layout (common head/body structure)
│       │   └── base_templ.go        # Generated Go file from base.templ
│       └── pages
│           ├── 404.templ            # 404 error page
│           ├── 404_templ.go         # Generated Go file from 404.templ
│           ├── index.templ          # Home page
│           ├── index_templ.go       # Generated Go file from index.templ
│           ├── register.templ       # Registration page (wraps form component)
│           └── register_templ.go    # Generated Go file from register.templ
├── static
│   └── css
│       ├── output
│       │   └── style.css            # Compiled Tailwind CSS
│       └── src
│           └── input.css            # Source Tailwind CSS with directives
├── store
│   └── store.go                     # Possibly legacy or global app store (review for duplication)
├── docker-compose.yml              # Docker services (e.g., DB, Redis, Mailhog)
├── go.mod                          # Go module file (dependencies)
├── go.sum                          # Checksums for Go dependencies
├── MakeFile                        # Automates tasks (e.g., `make dev`, `make build`)
├── migrations.go                   # DB migrations (may use something like golang-migrate or goose)
├── package.json                    # Node.js dependencies (e.g., Tailwind, PostCSS)
├── package-lock.json               # Exact versions of Node.js packages
├── README.md                       # Project documentation and setup instructions
├── server.go                       # Core server setup (router, middleware, static, etc.)
└── tailwind.config.js              # Tailwind CSS configuration

```
