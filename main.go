package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
)

type EmailBatch struct {
	Emails []string `json:"emails"`
}

type PhishingEmail struct {
	ID         string  `json:"id"`
	Subject    string  `json:"subject"`
	Sender     string  `json:"sender"`
	Date       string  `json:"date"`
	Confidence float64 `json:"confidence"`
	Status     string  `json:"status"` // "Phishing" or "Not Phishing"
}

var phishingEmails = []PhishingEmail{
	{
		ID:         "1",
		Subject:    "Confirm your credentials",
		Sender:     "badguy@phishy.com",
		Date:       "2025-04-21 10:30 PM",
		Confidence: 98.6,
		Status:     "Phishing",
	},
	{
		ID:         "2",
		Subject:    "Weekly Report",
		Sender:     "team@company.com",
		Date:       "2025-04-20 09:15 AM",
		Confidence: 10.2,
		Status:     "Not Phishing",
	},
}

func checkPhishing(emailBody string) (string, error) {
	payload := map[string][]string{
		"emails": {emailBody},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post("http://localhost:8000/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to call ML model: %v", err)
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode prediction: %v", err)
	}

	if len(result) > 0 {
		return result[0], nil
	}
	return "", fmt.Errorf("empty prediction response")
}

// func predict(c *fiber.Ctx) error {
// 	var data EmailBatch
// 	if err := c.BodyParser(&data); err != nil {
// 		log.Println("Error parsing batch:", err)
// 		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
// 	}

// 	results := []string{}
// 	for _, body := range data.Emails {
// 		results = append(results, checkPhishing(body))
// 	}

// 	log.Println("Emails scanned:", len(data.Emails))
// 	return c.JSON(results)
// }

func predict(c *fiber.Ctx) error {
	var data EmailBatch
	if err := c.BodyParser(&data); err != nil {
		log.Println("Error parsing batch:", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	results := []string{}
	for _, body := range data.Emails {
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
	return c.JSON(phishingEmails)
}

func main() {

	// Only load .env locally, skip in production
	if os.Getenv("RENDER") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("Could not load .env file (probably running on Render)")
		}
	}

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowMethods: "GET,POST,OPTIONS",
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

	log.Println("Server running on http://127.0.0.1:8000")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Fatal(app.Listen(":" + port))
}
