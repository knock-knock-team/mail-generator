package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"mime"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type captchaEntry struct {
	answer  int
	expires time.Time
}

type captchaStore struct {
	mu    sync.Mutex
	items map[string]captchaEntry
}

func newCaptchaStore() *captchaStore {
	return &captchaStore{items: make(map[string]captchaEntry)}
}

func (cs *captchaStore) set(token string, answer int, ttl time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.items[token] = captchaEntry{answer: answer, expires: time.Now().Add(ttl)}
}

func (cs *captchaStore) verify(token string, answer int) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	entry, ok := cs.items[token]
	if !ok {
		return false
	}
	delete(cs.items, token)
	if time.Now().After(entry.expires) {
		return false
	}
	return entry.answer == answer
}

func (cs *captchaStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	for token, entry := range cs.items {
		if now.After(entry.expires) {
			delete(cs.items, token)
		}
	}
}

type captchaResponse struct {
	Token    string `json:"token"`
	Question string `json:"question"`
}

type submitRequest struct {
	RequestType   string `json:"requestType"`
	LastName      string `json:"lastName"`
	FirstName     string `json:"firstName"`
	MiddleName    string `json:"middleName"`
	Phone         string `json:"phone"`
	Email         string `json:"email"`
	SerialNumber  string `json:"serialNumber"`
	Inn           string `json:"inn"`
	Message       string `json:"message"`
	Consent       bool   `json:"consent"`
	CaptchaToken  string `json:"captchaToken"`
	CaptchaAnswer string `json:"captchaAnswer"`
}

type submitResponse struct {
	OK     bool              `json:"ok"`
	Errors map[string]string `json:"errors,omitempty"`
}

type configResponse struct {
	CompanyName  string `json:"companyName"`
	SupportEmail string `json:"supportEmail"`
	SupportPhone string `json:"supportPhone"`
}

var (
	phoneDigits = regexp.MustCompile(`\d`)
	innDigits   = regexp.MustCompile(`^\d+$`)
)

func main() {
	mathrand.Seed(time.Now().UnixNano())
	_ = loadDotEnv(".env", "../.env")

	captcha := newCaptchaStore()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, configResponse{
			CompanyName:  os.Getenv("COMPANY_NAME"),
			SupportEmail: os.Getenv("SUPPORT_EMAIL"),
			SupportPhone: os.Getenv("SUPPORT_PHONE"),
		})
	})

	mux.HandleFunc("/api/captcha", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		captcha.cleanup()
		token, err := randomToken(16)
		if err != nil {
			http.Error(w, "captcha error", http.StatusInternalServerError)
			return
		}
		a := mathrand.Intn(8) + 1
		b := mathrand.Intn(8) + 1
		answer := a + b
		captcha.set(token, answer, 10*time.Minute)
		writeJSON(w, http.StatusOK, captchaResponse{Token: token, Question: fmt.Sprintf("Сколько будет %d + %d?", a, b)})
	})

	mux.HandleFunc("/api/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req submitRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		errorsMap := validateRequest(req, captcha)
		if len(errorsMap) > 0 {
			writeJSON(w, http.StatusBadRequest, submitResponse{OK: false, Errors: errorsMap})
			return
		}

		if err := sendEmail(req); err != nil {
			log.Printf("email send failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, submitResponse{OK: false, Errors: map[string]string{"server": "email"}})
			return
		}

		log.Printf("email sent successfully to %s", os.Getenv("MAIL_TO"))
		writeJSON(w, http.StatusOK, submitResponse{OK: true})
	})

	staticDir := resolveFrontendDir()
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	addr := ":8080"
	log.Printf("server running on %s", addr)
	log.Printf("serving frontend from %s", staticDir)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func loadDotEnv(paths ...string) error {
	var lastErr error
	for _, path := range paths {
		if path == "" {
			continue
		}
		stat, err := os.Stat(path)
		if err != nil {
			lastErr = err
			continue
		}
		if stat.IsDir() {
			continue
		}
		if err := parseDotEnvFile(path); err != nil {
			return err
		}
		return nil
	}
	return lastErr
}

func parseDotEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	return nil
}

func validateRequest(req submitRequest, captcha *captchaStore) map[string]string {
	errorsMap := make(map[string]string)

	if strings.TrimSpace(req.Phone) == "" {
		errorsMap["phone"] = "required"
	} else if countDigits(req.Phone) < 7 {
		errorsMap["phone"] = "format"
	}

	if strings.TrimSpace(req.Email) == "" {
		errorsMap["email"] = "required"
	} else if _, err := mail.ParseAddress(req.Email); err != nil {
		errorsMap["email"] = "format"
	}

	if strings.TrimSpace(req.Message) == "" {
		errorsMap["message"] = "required"
	}

	if strings.TrimSpace(req.Inn) != "" && !innDigits.MatchString(req.Inn) {
		errorsMap["inn"] = "format"
	}

	if !req.Consent {
		errorsMap["consent"] = "required"
	}

	answer, err := parseCaptcha(req.CaptchaAnswer)
	if err != nil || strings.TrimSpace(req.CaptchaToken) == "" || !captcha.verify(req.CaptchaToken, answer) {
		errorsMap["captcha"] = "invalid"
	}

	return errorsMap
}

func parseCaptcha(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("empty")
	}
	var result int
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("not digit")
		}
		result = result*10 + int(r-'0')
	}
	return result, nil
}

func countDigits(value string) int {
	return len(phoneDigits.FindAllString(value, math.MaxInt))
}

func sendEmail(req submitRequest) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	to := os.Getenv("MAIL_TO")

	if host == "" || port == "" || user == "" || pass == "" || from == "" || to == "" {
		return errors.New("missing smtp env")
	}

	log.Printf("SMTP config: host=%s, port=%s, user=%s, from=%s", host, port, user, from)

	subject := fmt.Sprintf("Заявка: %s %s", strings.TrimSpace(req.LastName), strings.TrimSpace(req.FirstName))
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)

	body := strings.Builder{}
	body.WriteString("Новая заявка с сайта\n\n")
	body.WriteString(fmt.Sprintf("Тип обращения: %s\n", req.RequestType))
	body.WriteString(fmt.Sprintf("Фамилия: %s\n", req.LastName))
	body.WriteString(fmt.Sprintf("Имя: %s\n", req.FirstName))
	body.WriteString(fmt.Sprintf("Отчество: %s\n", req.MiddleName))
	body.WriteString(fmt.Sprintf("Телефон: %s\n", req.Phone))
	body.WriteString(fmt.Sprintf("Email: %s\n", req.Email))
	body.WriteString(fmt.Sprintf("Заводской номер прибора: %s\n", req.SerialNumber))
	body.WriteString(fmt.Sprintf("ИНН компании: %s\n", req.Inn))
	body.WriteString("Сообщение:\n")
	body.WriteString(req.Message)
	body.WriteString("\n\n")
	body.WriteString(fmt.Sprintf("Время: %s\n", time.Now().Format(time.RFC3339)))

	msg := strings.Builder{}
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body.String())

	addr := fmt.Sprintf("%s:%s", host, port)
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	var client *smtp.Client

	if p == 465 {
		// SMTPS: direct TLS connection (Яндекс smtp.yandex.ru:465)
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
		})
		if err != nil {
			return fmt.Errorf("tls dial error: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("smtp client error: %w", err)
		}
		defer client.Close()
	} else {
		// STARTTLS: plain connection then upgrade (587)
		var err error
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dial error: %w", err)
		}
		defer client.Close()

		// Upgrade to TLS
		if err := client.StartTLS(&tls.Config{
			ServerName: host,
		}); err != nil {
			return fmt.Errorf("starttls error: %w", err)
		}
	}

	// Authenticate
	auth := smtp.PlainAuth("", user, pass, host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth error: %w", err)
	}

	// Send mail
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail error: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt error: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data error: %w", err)
	}
	defer w.Close()

	_, err = w.Write([]byte(msg.String()))
	if err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	_ = client.Quit()
	return nil
}

func resolveFrontendDir() string {
	candidates := []string{"frontend", "../frontend"}
	for _, dir := range candidates {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return dir
		}
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		for _, dir := range []string{filepath.Join(exeDir, "frontend"), filepath.Join(exeDir, "..", "frontend")} {
			if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
				return dir
			}
		}
	}
	return "./"
}

func randomToken(size int) (string, error) {
	if size <= 0 {
		return "", errors.New("size")
	}
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
