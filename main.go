package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"phishing_api/database"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"github.com/microcosm-cc/bluemonday"
)

type EmailBatch struct {
	Emails []string `json:"emails"`
}

func checkPhishing(emailBody string) (string, error) {
	p := bluemonday.StrictPolicy()
	cleanText := p.Sanitize(emailBody)

	payload := map[string][]string{
		"emails": {cleanText},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post("http://localhost:8001/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to call ML model: %v", err)
	}
	defer resp.Body.Close()

	// 🔍 Read raw response for logging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	log.Println("📨 checkPhishing received body:", cleanText)
	log.Println("📬 Raw response from ML model:", string(bodyBytes))

	// 🔁 Try decoding into []string
	var result []string
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return "", fmt.Errorf("failed to decode prediction: %v", err)
	}

	if len(result) > 0 {
		return result[0], nil
	}
	return "", fmt.Errorf("empty prediction response")
}

func predict(c *fiber.Ctx) error {
	var data EmailBatch
	if err := c.BodyParser(&data); err != nil {
		log.Println("Error parsing batch:", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	results := []string{}
	for _, body := range data.Emails {
		log.Println("📤 Email being scanned:", body)
		result, err := checkPhishing(body)
		if err != nil {
			log.Println("Prediction failed:", err)
			results = append(results, "error")
		} else {
			results = append(results, result)
		}
	}

	log.Println("Emails scanned:", len(data.Emails))
	return c.JSON(results)
}

func whoami(c *fiber.Ctx) error {
	token := tokenStore["user"]
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return c.SendString(string(body))
}

func getPhishingEmails(c *fiber.Ctx) error {
	// Check if user is authenticated

	authHeader := c.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		log.Println("[Backend] Missing or malformed Authorization header")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authorization header required",
		})
	}
	token := authHeader[7:]

	if token == "" {
		log.Println("[Backend] Error: User not authenticated")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	// Get user_email from query parameters
	userEmail := c.Query("user_email")
	if userEmail == "" {
		log.Println("[Backend] Error: User email is required")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "User email is required",
		})
	}

	// Verify the authenticated user matches the requested email
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[Backend] Error verifying user: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify user",
		})
	}
	defer resp.Body.Close()

	var userInfo struct {
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("[Backend] Error decoding user info: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decode user info",
		})
	}

	if !strings.EqualFold(userInfo.UserPrincipalName, userEmail) {
		log.Printf("[Backend] Error: User %s tried to access emails for %s", userInfo.UserPrincipalName, userEmail)
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "Not authorized to access these emails",
		})
	}

	log.Printf("[Backend] Fetching emails for user: %s", userEmail)

	var emails []database.ScannedEmail
	// Sort by the actual email date, most recent first
	if err := database.DB.Where("user_email = ?", userEmail).Order("date DESC").Find(&emails).Error; err != nil {
		log.Printf("[Backend] Error fetching emails: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch emails",
		})
	}

	log.Printf("[Backend] Found %d emails for user %s", len(emails), userEmail)
	return c.JSON(emails)
}

func storeEmail(c *fiber.Ctx) error {
	var email database.ScannedEmail
	if err := c.BodyParser(&email); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Set the current timestamp
	email.CreatedAt = time.Now().Unix()

	// Store in database
	if err := database.DB.Create(&email).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store email",
		})
	}

	return c.JSON(email)
}

func getEmails(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	var emails []database.ScannedEmail
	if err := database.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&emails).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve emails",
		})
	}

	return c.JSON(emails)
}

type UpdateStatusRequest struct {
	Status string `json:"status"`
}

func updateEmailStatus(c *fiber.Ctx) error {
	emailID := c.Params("id")
	if emailID == "" {
		log.Println("[Backend] Error: Email ID is required")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Email ID is required",
		})
	}

	log.Printf("[Backend] Received update request for email ID: %s", emailID)

	var req UpdateStatusRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[Backend] Error parsing request body: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	log.Printf("[Backend] Request body: %+v", req)

	var email database.ScannedEmail
	if err := database.DB.First(&email, emailID).Error; err != nil {
		log.Printf("[Backend] Error finding email: %v", err)
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Email not found",
		})
	}

	log.Printf("[Backend] Found email before update: ID=%d, Status=%s", email.ID, email.Status)

	if req.Status != "Phishing" && req.Status != "Safe" {
		log.Printf("[Backend] Invalid status value: %s", req.Status)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid status value",
		})
	}
	email.Status = req.Status

	log.Printf("[Backend] Attempting to update email: ID=%d, New Status=%s", email.ID, email.Status)

	result := database.DB.Save(&email)
	if result.Error != nil {
		log.Printf("[Backend] Error updating email status: %v", result.Error)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update email status",
		})
	}

	log.Printf("[Backend] Database update result - Rows affected: %d, Error: %v", result.RowsAffected, result.Error)

	// Verify the update by fetching the email again
	var updatedEmail database.ScannedEmail
	if err := database.DB.First(&updatedEmail, emailID).Error; err != nil {
		log.Printf("[Backend] Error verifying update: %v", err)
	} else {
		log.Printf("[Backend] Verified email after update: ID=%d, Status=%s", updatedEmail.ID, updatedEmail.Status)
	}

	return c.JSON(updatedEmail)
}

type StoreEmailRequest struct {
	UserEmail string `json:"user_email"`
	Subject   string `json:"subject"`
	Sender    string `json:"sender"`
	Date      string `json:"date"`
	Body      string `json:"body"`
	Status    string `json:"status"`
}

func storeScannedEmail(c *fiber.Ctx) error {
	var req StoreEmailRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[Backend] Error parsing request: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	log.Printf("[Backend] Checking for existing email for user: %s", req.UserEmail)

	// Check if email already exists
	var existingEmail database.ScannedEmail
	result := database.DB.Where("user_email = ? AND subject = ? AND sender = ? AND date = ?",
		req.UserEmail, req.Subject, req.Sender, req.Date).First(&existingEmail)

	if result.Error == nil {
		// Email exists, update its status and confidence if needed
		log.Printf("[Backend] Email already exists with ID: %d", existingEmail.ID)

		// Only update if the new confidence is higher or status is different
		if req.Status != existingEmail.Status {
			existingEmail.Status = req.Status
			existingEmail.CreatedAt = time.Now().Unix()

			if err := database.DB.Save(&existingEmail).Error; err != nil {
				log.Printf("[Backend] Error updating existing email: %v", err)
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to update existing email",
				})
			}
			log.Printf("[Backend] Updated existing email with ID: %d", existingEmail.ID)
			return c.JSON(existingEmail)
		}

		// If no updates needed, return the existing email
		return c.JSON(existingEmail)
	}

	// Email doesn't exist, create new entry
	email := database.ScannedEmail{
		UserEmail: req.UserEmail,
		Subject:   req.Subject,
		Sender:    req.Sender,
		Date:      req.Date,
		Body:      req.Body,
		Status:    req.Status,
		CreatedAt: time.Now().Unix(),
	}

	if err := database.DB.Create(&email).Error; err != nil {
		log.Printf("[Backend] Error storing new email: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store email",
		})
	}

	log.Printf("[Backend] Successfully stored new email with ID: %d", email.ID)
	return c.JSON(email)
}

func main() {
	// Only load .env locally, skip in production
	if os.Getenv("RENDER") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("Could not load .env file (probably running on Render)")
		}
	}

	// Initialize database
	database.InitDB()

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PATCH,OPTIONS",
	}))

	app.Get("/auth", startAuth)
	app.Get("/callback", handleCallback)
	app.Post("/subscribe", createSubscription)
	app.Get("/subscribe", createSubscription)
	app.Get("/notifications", handleNotification)
	app.Post("/notifications", handleNotification)
	app.Post("/predict", predict)
	app.Get("/me", whoami)
	app.Get("/phishing-emails", getPhishingEmails)
	app.Post("/store-email", storeEmail)
	app.Get("/emails", getEmails)
	app.Patch("/update-email-status/:id", updateEmailStatus)
	app.Post("/store-scanned-email", storeScannedEmail)

	log.Println("Server running on http://127.0.0.1:8000")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Fatal(app.Listen(":" + port))
}
