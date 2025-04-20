package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type GraphNotification struct {
	Value []struct {
		Resource string `json:"resource"`
	} `json:"value"`
}

func handleNotification(c *fiber.Ctx) error {
	validationToken := c.Query("validationToken")
	if validationToken != "" {
		log.Println("Responding to Microsoft Graph validation request")
		return c.SendString(validationToken)
	}

	// Handle actual notifications later
	log.Println("Received a real notification (not validation)")
	return c.SendStatus(202)
}


func fetchEmailBody(messageID, token string) (string, error) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/messages/%s", messageID)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var email map[string]interface{}
	if err := json.Unmarshal(body, &email); err != nil {
		return "", err
	}

	content := ""
	if bodyContent, ok := email["body"].(map[string]interface{}); ok {
		if value, ok := bodyContent["content"].(string); ok {
			content = value
		}
	}

	return content, nil
}

func scanEmail(emailBody string) error {
	payload := map[string][]string{
		"emails": {emailBody},
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post("https://phishing-api-i4kq.onrender.com/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Println("🔍 Prediction result:", string(respBody))

	return nil
}
