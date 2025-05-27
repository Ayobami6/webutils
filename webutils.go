package webutils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gopkg.in/gomail.v2"
)

// RedudisCacheService implements CacheService interface
type RedisCacheService struct {
	// inject redis client
	client *redis.Client
}

// NewRedisCacheService creates a new RedisCacheService
// with the provided redis client.
func NewRedisCacheService(client *redis.Client) *RedisCacheService {
	return &RedisCacheService{client: client}
}

func GetEnv(key string, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return fallback
	}
	return value
}

// Implement CacheService interface methods
// Set sets the value of the provided key with an expiration time.
func (s *RedisCacheService) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return s.client.Set(ctx, key, value, expiration).Err()
}

// Get returns the value of the provided key.
// If the key does not exist, an empty string is returned.
func (s *RedisCacheService) Get(ctx context.Context, key string) (string, error) {
	return s.client.Get(ctx, key).Result()
}

// Response is a utility function that generates a standard response format for restful APIs.
// It takes a status code, data, and message as input parameters.
// It returns a map containing the status, data, message, and status code.
func Response(statusCode int, data any, message any) map[string]any {
	var status string
	switch {
	case statusCode >= 200 && statusCode <= 299:
		status = "success"
	case statusCode == 400:
		status = "error"
	case statusCode >= 300 && statusCode <= 399:
		status = "redirect"
	case statusCode == 404:
		status = "not found"
	case statusCode >= 405 && statusCode <= 499:
		status = "error"
	case statusCode == 401 || statusCode == 403:
		status = "unauthorized"
	case statusCode >= 500:
		status = "error"
		message = "This is from us!, please contact admin"
	default:
		status = "error"
		message = "This is from us!, please contact admin"
	}
	res := map[string]any{
		"status":      status,
		"data":        data,
		"message":     message,
		"status_code": statusCode,
	}
	return res

}

// GetTokenFromRequest extracts the access token from the request context.
// It checks for the presence of the "Authorization" header and validates its format.
// If the token is present and valid, it returns the token.
func GetTokenFromRequest(c *gin.Context) (string, error) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		return "", errors.New("authorization header not provided")
	}

	fields := strings.Fields(authorizationHeader)
	if len(fields) < 2 {
		return "", errors.New("invalid authorization header format")
	}

	authorizationType := strings.ToLower(fields[0])
	if authorizationType != "bearer" {
		return "", errors.New("unsupported authorization type")
	}

	accessToken := fields[1]
	return accessToken, nil
}

// GetUserFromContext extracts the user from the request context.
// It checks for the presence of the "user" key in the context.
// If the user is found, it returns the user object.
func GetUserFromContext(c *gin.Context) (any, error) {
	user, exists := c.Get("user")
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GenerateOTP generates a random 6-digit OTP.
func GenerateOTP() string {
	rand.Seed(time.Now().UnixNano())
	otp := rand.Intn(900000) + 100000
	return strconv.Itoa(otp)
}

func Forbidden(c *gin.Context) {
	c.JSON(http.StatusForbidden, Response(http.StatusForbidden, nil, "Unauthorized"))
	c.Abort()
}

// MailerService implements Mailer interface
type MailerService struct {
}

// NewMailerService creates a new MailerService
func NewMailerService() *MailerService {
	return &MailerService{}
}

type MailerCredentials struct {
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
}

// NewMailCredentials creates a new MailerCredentials
// with the provided SMTP host, port, user, and password.
func NewMailCredentials(smtpHost string, smtpPort int, smtpUser string, smtpPass string) MailerCredentials {
	return MailerCredentials{
		SMTPHost: smtpHost,
		SMTPPort: smtpPort,
		SMTPUser: smtpUser,
		SMTPPass: smtpPass,
	}
}

// SendMail sends an email using the provided parameters.
func (s *MailerService) SendMail(ctx context.Context, to, from, subject, username, message, templateName string, mailCred MailerCredentials) error {
	// Implement the logic to send an email
	templ, err := os.ReadFile(fmt.Sprintf("internal/utils/templates/%s.html", templateName))
	if err != nil {
		log.Println("Error reading email template:", err)
		return err
	}
	t, err := template.New("email").Parse(string(templ))
	if err != nil {
		log.Println("Error parsing email template:", err)
		return err
	}
	// mail data
	mailData := map[string]interface{}{
		"Username": username,
		"Message":  message,
	}
	// write the maildata to bytes buffer
	buf := new(bytes.Buffer)
	err = t.Execute(buf, mailData)
	if err != nil {
		log.Println("Error executing email template:", err)
		return err
	}
	m := gomail.NewMessage()

	// Set email headers
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	// Set the HTML body
	m.SetBody("text/html", buf.String())
	smtpHost := mailCred.SMTPHost
	smtpPort := mailCred.SMTPPort
	smtpUser := mailCred.SMTPUser
	smtpPass := mailCred.SMTPPass

	// Create a new SMTP dialer
	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)
	d.SSL = true

	// Send the email and handle errors
	if err := d.DialAndSend(m); err != nil {
		fmt.Println("Error sending email:", err)
		return err
	}

	// Success message
	slog.Info("Email sent successfully", "to", to, "subject", subject)

	return nil
}

type CodeGeneratorService struct{}

// NewCodeGeneratorService creates a new CodeGeneratorService
func NewCodeGeneratorService() *CodeGeneratorService {
	return &CodeGeneratorService{}
}

// GenerateCode generates a random 4-digit code.
func (cg *CodeGeneratorService) GenerateCode() int {
	// get random four digit code
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(9000) + 1000
	return code
}

// GenerateReferenceCode generates a random 10-character alphanumeric reference code.
func (cg *CodeGeneratorService) GenerateReferenceCode() string {
	// generate randm aplhanumeric code
	rand.Seed(time.Now().UnixNano())
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// HandlerInternalServerError Gin Middleware
func HandleInternalServerError(message string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 {
			_ = c.Errors[0].Err
			c.JSON(http.StatusInternalServerError, Response(http.StatusInternalServerError, nil, message))
			c.Abort()
		}
	}
}

func HandleError(err error) {
	if err != nil {
		// log error
		log.Println(err)
	}
}

// Request struct represents an HTTP request to be sent to the Azure OpenAI API
type Request struct {
	ctx     context.Context
	body    any
	method  string
	url     string
	headers map[string]interface{}
}

// It contains the request body, method, URL, and headers.
// The body can be of any type, and the headers are a map of string keys to interface{} values.
// The method is the HTTP method (e.g., GET, POST) to be used for the request.
// The URL is the endpoint of the Azure OpenAI API to which the request will be sent.
// The headers are optional and can be used to set any additional headers required by the API.
func NewRequest(method string, url string, body any, headers map[string]interface{}, ctx context.Context) *Request {
	return &Request{
		body:    body,
		method:  method,
		url:     url,
		headers: headers,
		ctx:     ctx,
	}
}

// The Request struct is used to create and send requests to the Azure OpenAI API.
// It has a method Send() that sends the request and returns the response.
func (r *Request) Send() (*http.Response, error) {
	data, err := json.Marshal(r.body)
	if err != nil {
		log.Printf("Error marshalling request body: %v", err)
		return nil, err
	}
	client := &http.Client{}
	method := strings.ToUpper(r.method)
	req, err := http.NewRequestWithContext(r.ctx, method, r.url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return nil, err
	}

	for key, value := range r.headers {
		req.Header.Set(key, value.(string))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type CustomLoggerSDK struct {
	endpoint *string
}

// NewCustomLoggerSDK creates a new CustomLoggerSDK instance
func NewCustomLoggerSDK(endpoint *string) *CustomLoggerSDK {
	return &CustomLoggerSDK{endpoint: endpoint}
}

func ToBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func JsonDecoder(v any, reader *io.Reader) error {
	// just decode in memory
	err := json.NewDecoder(*reader).Decode(v)
	if err != nil {
		log.Println("Error decoding JSON:", err)
		return err
	}
	return nil
}

// Log logs the provided endpoint to the console
func (l *CustomLoggerSDK) Log(severity, appName string, traceback error) error {
	if l.endpoint != nil {
		//  send and api request to and endpoint
		// create the request body
		payload := LogRequestPayload{
			Severity:  severity,
			AppName:   appName,
			Traceback: traceback.Error(),
		}
		// convert the payload to bytes
		data, err := ToBytes(payload)
		if err != nil {
			log.Printf("Error marshalling payload: %v", err)
			return err
		}
		// set up context withe 20 sec timeout
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// set up headers
		headers := map[string]interface{}{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		}
		// set up request
		req := NewRequest("POST", *l.endpoint, bytes.NewBuffer(data), headers, ctx)
		// send the request
		resp, err := req.Send()
		if err != nil {
			log.Printf("Error sending request: %v", err)
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			log.Printf("Error: received status code %d", resp.StatusCode)
			return fmt.Errorf("received status code %d", resp.StatusCode)
		}
		return nil
	}
	return nil
}
