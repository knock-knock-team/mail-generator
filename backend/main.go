package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"mime"
	"mime/multipart"
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

type quoteRequest struct {
	LastName      string
	FirstName     string
	MiddleName    string
	Phone         string
	Email         string
	Inn           string
	CompanyName   string
	Project       string
	Message       string
	Consent       bool
	CaptchaToken  string
	CaptchaAnswer string
}

type attachment struct {
	Field       string
	Filename    string
	ContentType string
	Data        []byte
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

	mux.HandleFunc("/api/quote", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		const maxTotalUpload = 50 << 20
		r.Body = http.MaxBytesReader(w, r.Body, maxTotalUpload+2<<20)
		if err := r.ParseMultipartForm(maxTotalUpload + 2<<20); err != nil {
			writeJSON(w, http.StatusBadRequest, submitResponse{OK: false, Errors: map[string]string{"files": "size"}})
			return
		}

		req := quoteRequest{
			LastName:      r.FormValue("lastName"),
			FirstName:     r.FormValue("firstName"),
			MiddleName:    r.FormValue("middleName"),
			Phone:         r.FormValue("phone"),
			Email:         r.FormValue("email"),
			Inn:           r.FormValue("inn"),
			CompanyName:   r.FormValue("companyName"),
			Project:       r.FormValue("project"),
			Message:       r.FormValue("message"),
			Consent:       r.FormValue("consent") == "on",
			CaptchaToken:  r.FormValue("captchaToken"),
			CaptchaAnswer: r.FormValue("captchaAnswer"),
		}

		attachments, totalSize, err := readMultipartFiles(r.MultipartForm, maxTotalUpload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, submitResponse{OK: false, Errors: map[string]string{"files": "size"}})
			return
		}

		errorsMap := validateQuoteRequest(req, captcha, totalSize, maxTotalUpload)
		if len(errorsMap) > 0 {
			writeJSON(w, http.StatusBadRequest, submitResponse{OK: false, Errors: errorsMap})
			return
		}

		if err := sendQuoteEmail(req, attachments); err != nil {
			log.Printf("quote email send failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, submitResponse{OK: false, Errors: map[string]string{"server": "email"}})
			return
		}

		log.Printf("quote email sent successfully to %s", os.Getenv("MAIL_TO"))
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

	if strings.TrimSpace(req.Inn) != "" && !isServiceRequest(req) && !innDigits.MatchString(req.Inn) {
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

func validateQuoteRequest(req quoteRequest, captcha *captchaStore, totalSize int64, maxTotal int64) map[string]string {
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

	if strings.TrimSpace(req.Inn) == "" {
		errorsMap["inn"] = "required"
	} else if !innDigits.MatchString(req.Inn) {
		errorsMap["inn"] = "format"
	}

	if strings.TrimSpace(req.CompanyName) == "" {
		errorsMap["companyName"] = "required"
	}

	if strings.TrimSpace(req.Project) == "" {
		errorsMap["project"] = "required"
	}

	if strings.TrimSpace(req.Message) == "" {
		errorsMap["message"] = "required"
	}

	if !req.Consent {
		errorsMap["consent"] = "required"
	}

	if totalSize > maxTotal {
		errorsMap["files"] = "size"
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
	subject := fmt.Sprintf("Заявка: %s %s", strings.TrimSpace(req.LastName), strings.TrimSpace(req.FirstName))
	body := strings.Builder{}
	body.WriteString("Новая заявка с сайта\n\n")
	body.WriteString(fmt.Sprintf("Тип обращения: %s\n", req.RequestType))
	body.WriteString(fmt.Sprintf("Фамилия: %s\n", req.LastName))
	body.WriteString(fmt.Sprintf("Имя: %s\n", req.FirstName))
	body.WriteString(fmt.Sprintf("Отчество: %s\n", req.MiddleName))
	body.WriteString(fmt.Sprintf("Телефон: %s\n", req.Phone))
	body.WriteString(fmt.Sprintf("Email: %s\n", req.Email))
	serialLabel := "Заводской номер прибора"
	innLabel := "ИНН компании"
	if isServiceRequest(req) {
		serialLabel = "Название компании"
		innLabel = "Страна/регион"
	}
	body.WriteString(fmt.Sprintf("%s: %s\n", serialLabel, req.SerialNumber))
	body.WriteString(fmt.Sprintf("%s: %s\n", innLabel, req.Inn))
	body.WriteString("Сообщение:\n")
	body.WriteString(req.Message)
	body.WriteString("\n\n")
	body.WriteString(fmt.Sprintf("Время: %s\n", time.Now().Format(time.RFC3339)))

	return sendMailMessage(subject, body.String(), nil)
}

func sendQuoteEmail(req quoteRequest, attachments []attachment) error {
	subject := fmt.Sprintf("Запрос КП: %s %s", strings.TrimSpace(req.LastName), strings.TrimSpace(req.FirstName))
	body := strings.Builder{}
	body.WriteString("Новый запрос КП\n\n")
	body.WriteString(fmt.Sprintf("Фамилия: %s\n", req.LastName))
	body.WriteString(fmt.Sprintf("Имя: %s\n", req.FirstName))
	body.WriteString(fmt.Sprintf("Отчество: %s\n", req.MiddleName))
	body.WriteString(fmt.Sprintf("Телефон: %s\n", req.Phone))
	body.WriteString(fmt.Sprintf("Email: %s\n", req.Email))
	body.WriteString(fmt.Sprintf("ИНН компании: %s\n", req.Inn))
	body.WriteString(fmt.Sprintf("Название компании: %s\n", req.CompanyName))
	body.WriteString(fmt.Sprintf("Проект: %s\n", req.Project))
	body.WriteString("Сообщение:\n")
	body.WriteString(req.Message)
	body.WriteString("\n\n")
	body.WriteString("Вложения:\n")
	body.WriteString(formatAttachmentList(attachments))
	body.WriteString(fmt.Sprintf("\nВремя: %s\n", time.Now().Format(time.RFC3339)))

	return sendMailMessage(subject, body.String(), attachments)
}

func sendMailMessage(subject string, body string, attachments []attachment) error {
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

	message, err := buildEmailMessage(subject, from, to, body, attachments)
	if err != nil {
		return err
	}

	return sendSMTPRawMessage(host, port, user, pass, from, to, message)
}

func buildEmailMessage(subject string, from string, to string, body string, attachments []attachment) (string, error) {
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)

	if len(attachments) == 0 {
		msg := strings.Builder{}
		msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
		msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
		msg.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
		msg.WriteString("MIME-Version: 1.0\r\n")
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(body)
		return msg.String(), nil
	}

	boundary, err := randomToken(12)
	if err != nil {
		return "", err
	}

	msg := strings.Builder{}
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)
	msg.WriteString("\r\n")

	for _, att := range attachments {
		if len(att.Data) == 0 {
			continue
		}
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", att.ContentType, att.Filename))
		msg.WriteString("Content-Transfer-Encoding: base64\r\n")
		msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
		msg.WriteString("\r\n")
		msg.WriteString(wrapBase64(att.Data))
		msg.WriteString("\r\n")
	}

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	return msg.String(), nil
}

func sendSMTPRawMessage(host string, port string, user string, pass string, from string, to string, message string) error {
	addr := fmt.Sprintf("%s:%s", host, port)
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	var client *smtp.Client

	if p == 465 {
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
		var err error
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dial error: %w", err)
		}
		defer client.Close()

		if err := client.StartTLS(&tls.Config{
			ServerName: host,
		}); err != nil {
			return fmt.Errorf("starttls error: %w", err)
		}
	}

	auth := smtp.PlainAuth("", user, pass, host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth error: %w", err)
	}

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

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	_ = client.Quit()
	return nil
}

func readMultipartFiles(form *multipart.Form, maxTotal int64) ([]attachment, int64, error) {
	var attachments []attachment
	var total int64
	if form == nil {
		return attachments, total, nil
	}

	fields := []string{"files"}
	for _, field := range fields {
		for _, fh := range form.File[field] {
			if fh == nil || fh.Filename == "" {
				continue
			}
			if fh.Size > 0 && total+fh.Size > maxTotal {
				return nil, total, fmt.Errorf("files too large")
			}
			file, err := fh.Open()
			if err != nil {
				return nil, total, err
			}
			data, err := io.ReadAll(io.LimitReader(file, maxTotal-total+1))
			file.Close()
			if err != nil {
				return nil, total, err
			}
			if int64(len(data)) == 0 {
				continue
			}
			if total+int64(len(data)) > maxTotal {
				return nil, total, fmt.Errorf("files too large")
			}
			total += int64(len(data))
			contentType := http.DetectContentType(data)
			filename := filepath.Base(fh.Filename)
			attachments = append(attachments, attachment{
				Field:       field,
				Filename:    filename,
				ContentType: contentType,
				Data:        data,
			})
		}
	}

	return attachments, total, nil
}

func wrapBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for len(encoded) > 76 {
		out.WriteString(encoded[:76])
		out.WriteString("\r\n")
		encoded = encoded[76:]
	}
	if len(encoded) > 0 {
		out.WriteString(encoded)
	}
	return out.String()
}

func formatAttachmentList(attachments []attachment) string {
	if len(attachments) == 0 {
		return "—\n"
	}
	var b strings.Builder
	for _, att := range attachments {
		b.WriteString(fmt.Sprintf("- Файл: %s (%s)\n", att.Filename, formatBytes(int64(len(att.Data)))))
	}
	return b.String()
}

func formatBytes(value int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
	)
	if value >= mb {
		return fmt.Sprintf("%.1f MB", float64(value)/float64(mb))
	}
	if value >= kb {
		return fmt.Sprintf("%.1f KB", float64(value)/float64(kb))
	}
	return fmt.Sprintf("%d B", value)
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

func isServiceRequest(req submitRequest) bool {
	return strings.EqualFold(strings.TrimSpace(req.RequestType), "Сервис")
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
