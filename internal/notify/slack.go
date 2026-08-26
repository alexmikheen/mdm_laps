// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

// internal/notify/slack.go
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SlackNotifier struct {
	webhookURL string
}

func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
	}
}

type SlackMessage struct {
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type Attachment struct {
	Color     string  `json:"color"`
	Title     string  `json:"title"`
	Text      string  `json:"text"`
	Fields    []Field `json:"fields,omitempty"`
	Timestamp int64   `json:"ts"`
	Footer    string  `json:"footer"`
}

type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (s *SlackNotifier) SendPasswordRotation(hostname, serial, adminUser, status string, err error) error {
	color := "good"
	title := "✅ LAPS Password Rotation Successful"

	if err != nil {
		color = "danger"
		title = "❌ LAPS Password Rotation Failed"
	}

	message := SlackMessage{
		Attachments: []Attachment{
			{
				Color: color,
				Title: title,
				Text:  fmt.Sprintf("Device: %s\nSerial: %s\nAdmin: %s", hostname, serial, adminUser),
				Fields: []Field{
					{Title: "Hostname", Value: hostname, Short: true},
					{Title: "Serial Number", Value: serial, Short: true},
					{Title: "Admin User", Value: adminUser, Short: true},
					{Title: "Status", Value: status, Short: true},
				},
				Timestamp: time.Now().Unix(),
				Footer:    "GoLAPS Security",
			},
		},
	}

	if err != nil {
		message.Attachments[0].Fields = append(message.Attachments[0].Fields, Field{
			Title: "Error",
			Value: err.Error(),
			Short: false,
		})
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status: %d", resp.StatusCode)
	}

	return nil
}
