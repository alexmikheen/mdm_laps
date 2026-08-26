// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

// internal/notify/email.go
package notify

import (
	"fmt"
	"gopkg.in/mail.v2"
)

type EmailNotifier struct {
	smtpHost string
	smtpPort int
	from     string
	to       string
	username string
	password string
}

func NewEmailNotifier(smtpHost string, smtpPort int, from, to, username, password string) *EmailNotifier {
	return &EmailNotifier{
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		from:     from,
		to:       to,
		username: username,
		password: password,
	}
}

func (e *EmailNotifier) SendPasswordRotation(hostname, serial, adminUser, status string, err error) error {
	subject := "LAPS Password Rotation"
	if err != nil {
		subject = "❌ LAPS Password Rotation Failed"
	} else {
		subject = "✅ LAPS Password Rotation Successful"
	}

	body := fmt.Sprintf(`
LAPS Password Rotation Report
=============================

Device Information:
  Hostname: %s
  Serial Number: %s
  Admin User: %s

Status: %s
`, hostname, serial, adminUser, status)

	if err != nil {
		body += fmt.Sprintf("\nError Details:\n%s\n", err.Error())
	}

	m := mail.NewMessage()
	m.SetHeader("From", e.from)
	m.SetHeader("To", e.to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := mail.NewDialer(e.smtpHost, e.smtpPort, e.username, e.password)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
