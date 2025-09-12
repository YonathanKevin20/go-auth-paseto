package handlers

import (
	"go-auth-paseto/models"
	"go-auth-paseto/repositories"
	"go-auth-paseto/utils"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username" validate:"required" example:"john_doe"`
	Password string `json:"password" validate:"required" example:"password123"`
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Username string `json:"username" validate:"required" example:"john_doe"`
	Password string `json:"password" validate:"required" example:"password123"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token string `json:"token" example:"v4.local.eyJhbGciOiJQQVNFVE8iLCJ0eXAiOiJKV1QifQ..."`
}

// UserResponse represents the user data response
type UserResponse struct {
	ID       uint   `json:"id" example:"1"`
	Username string `json:"username" example:"john_doe"`
	Role     string `json:"role" example:"operator"`
}

// MessageResponse represents a generic message response
type MessageResponse struct {
	Message string `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponseSwagger struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail represents error details
type ErrorDetail struct {
	Message string `json:"message"`
}

// SuccessResponse represents a generic success response with data
type SuccessResponse struct {
	Data any `json:"data"`
}

var userRepo repositories.UserRepository = &repositories.GormUserRepository{}

// Register godoc
//
//	@Summary		Register a new user
//	@Description	Create a new user account with username and password
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			request	body		RegisterRequest							true	"Registration credentials"
//	@Success		201		{object}	SuccessResponse{data=MessageResponse}	"User created successfully"
//	@Failure		400		{object}	ErrorResponseSwagger					"Invalid input or missing required fields"
//	@Failure		409		{object}	ErrorResponseSwagger					"Username already exists"
//	@Failure		500		{object}	ErrorResponseSwagger					"Internal server error"
//	@Router			/auth/register [post]
func Register(c *fiber.Ctx) error {
	input := new(RegisterRequest)
	if err := sonic.Unmarshal(c.Body(), &input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "Invalid input")
	}

	if input.Username == "" || input.Password == "" {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "Username and password are required")
	}

	// Check if user already exists
	existingUser, err := userRepo.FindByUsername(input.Username)
	if err == nil && existingUser != nil {
		return utils.ErrorResponse(c, fiber.StatusConflict, "Username already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Could not hash password")
	}

	user := &models.User{
		Username: input.Username,
		Password: string(hashedPassword),
	}

	if err := userRepo.Create(user); err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Failed to create user")
	}

	return utils.JSONResponse(c, fiber.StatusCreated, MessageResponse{Message: "User created successfully"})
}

// Login godoc
//
//	@Summary		Authenticate user
//	@Description	Authenticate user with username and password, returns PASETO token
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			request	body		LoginRequest						true	"Login credentials"
//	@Success		200		{object}	SuccessResponse{data=LoginResponse}	"Login successful, returns token"
//	@Failure		400		{object}	ErrorResponseSwagger				"Invalid input or missing required fields"
//	@Failure		401		{object}	ErrorResponseSwagger				"Invalid username or password"
//	@Failure		500		{object}	ErrorResponseSwagger				"Internal server error"
//	@Router			/auth/login [post]
func Login(c *fiber.Ctx) error {
	input := new(LoginRequest)
	if err := sonic.Unmarshal(c.Body(), &input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "Invalid input")
	}

	if input.Username == "" || input.Password == "" {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "Username and password are required")
	}

	user, err := userRepo.FindByUsername(input.Username)
	if err != nil || user == nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid password")
	}

	token, err := utils.GenerateToken(user)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Could not generate token")
	}

	return utils.JSONResponse(c, fiber.StatusOK, LoginResponse{Token: token})
}

// GetMe godoc
//
//	@Summary		Get current user profile
//	@Description	Get the profile information of the currently authenticated user
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Success		200	{object}	SuccessResponse{data=UserResponse}	"User profile retrieved successfully"
//	@Failure		401	{object}	ErrorResponseSwagger				"Unauthorized - invalid or missing token"
//	@Failure		404	{object}	ErrorResponseSwagger				"User not found"
//	@Failure		500	{object}	ErrorResponseSwagger				"Internal server error"
//	@Router			/auth/me [get]
func GetMe(c *fiber.Ctx) error {
	id := c.Locals("id").(uint)

	user, err := userRepo.FindByID(id)
	if err != nil || user == nil {
		return utils.ErrorResponse(c, fiber.StatusNotFound, "User not found")
	}

	return utils.JSONResponse(c, fiber.StatusOK, UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Role:     string(user.Role),
	})
}

// Logout godoc
//
//	@Summary		Logout user
//	@Description	Logout the current user by blacklisting their token
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Success		200	{object}	SuccessResponse{data=MessageResponse}	"Successfully logged out"
//	@Failure		401	{object}	ErrorResponseSwagger					"Unauthorized - invalid or missing token"
//	@Failure		500	{object}	ErrorResponseSwagger					"Internal server error"
//	@Router			/auth/logout [post]
func Logout(c *fiber.Ctx) error {
	jti := c.Locals("jti").(string)
	exp := c.Locals("exp").(time.Time)

	err := utils.TokenBlacklist.Add(jti, exp)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Could not blacklist token")
	}

	return utils.JSONResponse(c, fiber.StatusOK, MessageResponse{Message: "Successfully logged out"})
}
