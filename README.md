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
├── cmd                                    # Application entry points
│   └── main.go                           # Main application bootstrap
├── config                                # Configuration management
│   └── config.go                         # Environment variables, settings
├── db                                    # Database connection setup
│   └── db.go                             # DB initialization and pooling
├── internal                              # Private application code
│   ├── auth                              # Authentication system
│   │   └── auth.go                       # JWT handling, password hashing
│   ├── cache                             # Caching layer
│   │   └── cache.go                      # Redis/in-memory cache logic
│   ├── dtos                              # Data Transfer Objects
│   │   └── users_dto.go                  # User API request/response structs
│   ├── handlers                          # HTTP request handlers
│   │   ├── auth.handlers.go              # Login/register/logout endpoints
│   │   └── view.handlers.go              # Page rendering handlers
│   ├── middleware                        # HTTP middleware
│   │   └── user.go                       # Auth middleware, CORS, logging
│   ├── models                            # Domain models
│   │   └── users                         # User domain
│   │       └── users.go                  # User struct and business logic
│   ├── repositories                      # Data access layer
│   │   └── user.go                       # User CRUD operations
│   ├── routes                            # Route definitions
│   │   ├── auth.routes.go                # Authentication routes
│   │   ├── user.routes.go                # User management routes
│   │   └── view.routes.go                # Server-rendered page routes
│   ├── store                             # Database abstraction
│   │   └── db.go                         # Query builders, transactions
│   ├── utils                             # Utility functions
│   │   └── utils.go                      # Helpers, validators, formatters
│   └── views                             # Templ templates (server-side rendering)
│       ├── components                    # Reusable UI components
│       │   ├── loginform.templ           # Login form component
│       │   ├── loginform_templ.go        # Generated Go code from .templ
│       │   ├── navbar.templ              # Navigation bar component
│       │   ├── navbar_templ.go           # Generated Go code
│       │   ├── profilecard.templ         # User profile display card
│       │   ├── profilecard_templ.go      # Generated Go code
│       │   ├── registerform.templ        # Registration form component
│       │   └── registerform_templ.go     # Generated Go code
│       ├── layouts                       # Page layout templates
│       │   ├── base.templ                # Base HTML layout
│       │   └── base_templ.go             # Generated Go code
│       ├── pages                         # Full page templates
│       │   ├── 404.templ                 # 404 error page
│       │   ├── 404_templ.go              # Generated Go code
│       │   ├── index.templ               # Home page template
│       │   ├── index_templ.go            # Generated Go code
│       │   ├── login.templ               # Login page template
│       │   ├── login_templ.go            # Generated Go code
│       │   ├── profile.templ             # User profile page
│       │   ├── profile_templ.go          # Generated Go code
│       │   ├── register.templ            # Registration page template
│       │   └── register_templ.go         # Generated Go code
│       └── helpers.go                    # Template helper functions
├── static                                # Static web assets
│   ├── css                               # Stylesheets
│   │   ├── output                        # Compiled CSS
│   │   │   └── style.css                 # Final Tailwind CSS output
│   │   └── src                           # Source CSS
│   │       └── input.css                 # Tailwind CSS input file
│   └── js                                # JavaScript files
│       └── toast.js                      # Client-side notifications
├── docker-compose.yml                    # Container orchestration
├── go.mod                                # Go module definition
├── go.sum                                # Go module checksums
├── MakeFile                              # Build automation commands
├── migrations.go                         # Database schema migrations
├── package.json                          # Node.js dependencies (for Tailwind)
├── package-lock.json                     # Node.js dependency lock file
├── README.md                             # Project documentation
├── server.go                             # Main server setup and configuration
└── tailwind.config.js                    # Tailwind CSS configuration

```
