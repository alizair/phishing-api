package main

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "os"
    "time"

    "github.com/gofiber/fiber/v2"
)


func createSubscription(c *fiber.Ctx) error {
	token := tokenStore["user"]
	if token == "" {
		return c.Status(401).SendString("Not authenticated")
	}

	subReq := map[string]interface{}{
		"changeType":         "created",
		"notificationUrl":    os.Getenv("NOTIFICATION_URL"),
		"resource":           "me/mailFolders('Inbox')/messages",
		"expirationDateTime": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		"clientState":        "secretClientValue",
	}
	body, _ := json.Marshal(subReq)

	req, _ := http.NewRequest("POST", "https://graph.microsoft.com/v1.0/subscriptions", bytes.NewBuffer(body))
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	return c.SendString(string(respBody))
}
