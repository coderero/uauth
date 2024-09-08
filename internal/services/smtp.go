package services

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"

	_ "github.com/joho/godotenv/autoload"
	"gopkg.in/mail.v2"
)

var (
	host string = os.Getenv("SMTP_HOST")
	port string = os.Getenv("SMTP_PORT")
	from string = os.Getenv("SMTP_FROM")
	user string = os.Getenv("SMTP_USERNAME")
	pass string = os.Getenv("SMTP_PASSWORD")

	ErrSmtpNotConfigured = errors.New("smtp service not configured")
)

type SmtpService interface {
	// Send sends an email
	Send(ctx context.Context, to, subject, body string) error
}

// smtpService is the implementation of the SmtpService interface.
type smtpService struct {
	host string
	port int
	from string
	user string
	pass string
}

func NewSmtpService() SmtpService {
	p, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return &smtpService{
		host: host,
		port: p,
		from: from,
		user: user,
		pass: pass,
	}
}
func (s *smtpService) Send(ctx context.Context, to, subject, body string) error {
	// Create a channel to signal completion
	done := make(chan error, 1)

	m := mail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	log.Print(to)
	log.Print(from)
	log.Print(subject)
	log.Print(body)

	d := mail.NewDialer(s.host, s.port, s.user, s.pass)

	go func() {
		err := d.DialAndSend(m)
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
