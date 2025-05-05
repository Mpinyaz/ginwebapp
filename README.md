#Go Gin Web App

```
/yourapp
│
├── /cmd                  # Entry point (main.go)
│   └── main.go
│
├── /config               # Viper setup or env config
│
├── /internal             # Application logic
│   ├── /models           # DB models (GORM entities)
│   ├── /dtos             # Request/Response payloads
│   ├── /repositories     # Data access layer (interfaces + implementations)
│   │   └── user_repository.go
│   ├── /services         # Business logic layer
│   │   └── user_service.go
│   ├── /handlers         # HTTP controllers
│   │   └── user_handler.go
│   └── /routes           # Route registration (Gin or Echo)
│       └── routes.go
│
├── /migrations           # SQL migration files
├── go.mod
└── .env
```
