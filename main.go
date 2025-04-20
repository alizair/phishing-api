package main

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
)

type EmailBatch struct {
	Emails []string `json:"emails"`
}

func checkPhishing(emailBody string) string {
	if rand.Float32() > 0.5 {
		return "phishing"
	}
	return "safe"
}

func predict(c *fiber.Ctx) error {
	var data EmailBatch
	if err := c.BodyParser(&data); err != nil {
		log.Println("Error parsing batch:", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	results := []string{}
	for _, body := range data.Emails {
		results = append(results, checkPhishing(body))
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


	log.Println("Server running on http://127.0.0.1:8000")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Fatal(app.Listen(":" + port))
}
