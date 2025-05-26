package webutils

// define abstract interface for the Utils struct

import (
	"context"
	"time"
)

// CacheService interface defines two methods: Set and Get.
type CacheService interface {
	Set(ctx context.Context, email string, code int, expiration time.Duration) error
	Get(ctx context.Context, email string) (int, error)
}

// Malier interface defines two methods: GenerateCode and GenerateReferenceCode.
type Mailer interface {
	SendMail(ctx context.Context, to, from, subject, userName, message, templateName string, mailCred MailerCredentials) error
}

// CodeGenerator is an interface for generating codes and reference codes
type CodeGenerator interface {
	GenerateCode() int
	GenerateReferenceCode() string
}

type CustomLogger interface {
	Log(endpoint *string) error
}

type LogRequestPayload struct {
	Severity  string `json:"severity"`
	AppName   string `json:"app_name"`
	Traceback string `json:"traceback"`
}
