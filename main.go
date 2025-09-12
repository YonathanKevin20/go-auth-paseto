package main

import (
	"go-auth-paseto/config"
	"go-auth-paseto/handlers"
	"go-auth-paseto/middlewares"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "go-auth-paseto/docs"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/joho/godotenv"
)

// @title						Go Auth Paseto API
// @version					1.0
// @description				This is a sample server for a Go authentication system using Paseto tokens.
// @host						localhost:8080
// @BasePath					/api
// @schemes					http
//
// @securityDefinitions.apikey	Bearer
// @in							header
// @name						Authorization
// @description				Type "Bearer" followed by a space and PASETO token.
func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize Redis
	if err := config.InitRedis(); err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}
	defer config.RedisClient.Close()

	// Add a short delay before connecting to the database
	time.Sleep(2 * time.Second)

	// Connect to database
	_, err := config.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	// Run migrations
	if err := config.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		JSONEncoder: sonic.Marshal,
		JSONDecoder: sonic.Unmarshal,
	})
	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))
	// Set up routes
	setupRoutes(app)

	// Set up graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		_ = app.Shutdown()
	}()

	// Start server
	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}

func setupRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/api", fiber.StatusTemporaryRedirect)
	})
	app.Get("/api", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Welcome to the Go Auth Paseto API",
		})
	})
	// Swagger route with custom config
	app.Get("/docs/*", swagger.New(swagger.Config{
		Title: "Go Auth PASETO API Documentation",
	}))

	// Routes
	api := app.Group("/api")

	// Public routes
	api.Post("/auth/login", handlers.Login)
	api.Post("/auth/register", handlers.Register)

	// Protected routes
	api.Use(middlewares.AuthMiddleware)

	// Logout route
	api.Post("/auth/logout", handlers.Logout)

	// Get current user route
	api.Get("/auth/me", handlers.GetMe)
}
