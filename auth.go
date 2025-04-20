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
)

var (
	tokenStore = make(map[string]string)
)

func startAuth(c *fiber.Ctx) error {
	scope := os.Getenv("SCOPE")
	if scope == "" {
		scope = "https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Subscription.Read.All"
		log.Println("SCOPE not found in .env — using default scope.")
	}

	authURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query&scope=%s&prompt=consent&state=12345",
		os.Getenv("TENANT_ID"),
		os.Getenv("CLIENT_ID"),
		os.Getenv("REDIRECT_URI"),
		scope,
	)	

	log.Println("Redirecting to Microsoft OAuth with scope:", scope)
	return c.Redirect(authURL)
}

func handleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(400).SendString("Missing code")
	}

	scope := os.Getenv("SCOPE")
	if scope == "" {
		scope = "https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Subscription.Read.All"
	}

	data := fmt.Sprintf(
		"client_id=%s&scope=%s&code=%s&redirect_uri=%s&grant_type=authorization_code&client_secret=%s",
		os.Getenv("CLIENT_ID"),
		scope,
		code,
		os.Getenv("REDIRECT_URI"),
		os.Getenv("CLIENT_SECRET"),
	)	

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", os.Getenv("TENANT_ID")),
		bytes.NewBufferString(data),
	)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Token request failed:", err)
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Println("Token response:", string(body))

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return c.Status(500).SendString("Failed to retrieve access token")
	}

	tokenStore["user"] = accessToken
	return c.SendString("Auth successful. Now call /subscribe to register for notifications.")
}
