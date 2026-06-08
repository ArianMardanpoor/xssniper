package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Telegram ──────────────────────────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

// loadEnv reads a .env file and sets any unset env variables from it.
// Looks for .env next to the binary, then in the current working directory.
func loadEnv() {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	candidates = append(candidates, ".env")

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
		f.Close()
		logLine("INFO", cyan, "loaded .env from %s", path)
		return
	}
}

func newTelegram() *Telegram {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID}
}

func telegramClient() *http.Client {
	tr := &http.Transport{}

	// بررسی اینکه پراکسی ست شده باشد و کاربر آن را دستی "off" نکرده باشد
	if proxyURL != "" && strings.ToLower(proxyURL) != "off" {
		if p, err := url.Parse(proxyURL); err == nil {
			tr.Proxy = http.ProxyURL(p)
		} else {
			logLine("WARN", yellow, "invalid proxy URL structure: %v", err)
		}
	} else {
		// اگر کاربر دستی نوشت -proxy off، پراکسی کلاً غیرفعال می‌شود
		tr.Proxy = nil
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
}

func (tg *Telegram) send(text string) error {
	if tg == nil {
		return fmt.Errorf("telegram configuration is missing")
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.Token)

	payload := map[string]interface{}{
		"chat_id":                  tg.ChatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	client := telegramClient()
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err // خطاهای شبکه (مثل کانکت نشدن) اینجا مشخص می‌شود
	}
	defer resp.Body.Close()

	// خواندن دقیق خطاهای API تلگرام برای دیباگ راحت‌تر
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func (tg *Telegram) notify(targetURL string, findings []string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString("🚨 <b>XSS Finding!</b>\n\n")
	sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(targetURL)))
	sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n", ts))
	sb.WriteString(fmt.Sprintf("🔢 <b>Count:</b> %d unique endpoint(s)\n\n", len(findings)))
	sb.WriteString("<b>Details:</b>\n")

	for i, f := range findings {
		if f == "" {
			continue
		}

		// ۱. حذف کدهای رنگی ترمینال برای تمیزی پیام تلگرام
		cleanLine := stripANSI(f)

		// ۲. حذف محدودیت ۲۰۰ کاراکتری (یا افزایش آن به ۴۰۰۰ کاراکتر که سقف تلگرام است)
		// این کار باعث می‌شود کل URL آسیب‌پذیر به همراه پارامترها و پی‌لود ارسالی بدون کات شدن فرستاده شود.
		if len(cleanLine) > 3500 {
			cleanLine = cleanLine[:3500] + "… (truncated)"
		}

		sb.WriteString(fmt.Sprintf("<code>%d. %s</code>\n", i+1, escapeHTML(cleanLine)))
	}

	// بررسی وضعیت فعال بودن تلگرام و ارسال پیام
	var sendErr error
	if tg == nil {
		sendErr = fmt.Errorf("telegram client is nil (check your .env file or environment variables)")
	} else {
		sendErr = tg.send(sb.String())
	}

	// اگر ارسال ناموفق بود، در دایرکتوری مشخص شده لاگ ذخیره می‌شود
	if sendErr != nil {
		logLine("WARN", yellow, "telegram notify failed: %v", sendErr)

		homeDir, errHome := os.UserHomeDir()
		if errHome == nil {
			logDir := filepath.Join(homeDir, "tel_xssniper_notif")
			if errMkdir := os.MkdirAll(logDir, 0755); errMkdir == nil {
				timestamp := time.Now().Format("20060102_150405")
				logFile := filepath.Join(logDir, fmt.Sprintf("failed_notif_%s_%d.txt", timestamp, time.Now().Nanosecond()))

				logContent := fmt.Sprintf("FAILED TO SEND AT: %s\nREASON: %v\n-----------------------------------\n%s\n",
					time.Now().Format("2006-01-02 15:04:05"), sendErr, sb.String())

				if errWrite := os.WriteFile(logFile, []byte(logContent), 0644); errWrite == nil {
					logLine("INFO", cyan, "saved backup log to %s", logFile)
				}
			}
		}
	} else {
		logLine("TG", cyan, "notification sent to telegram ✓")
	}
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── ANSI colors ───────────────────────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	purple = "\033[35m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	white  = "\033[97m"
)

// ── State & Status ────────────────────────────────────────────────────────────

type PhaseStatus string

const (
	StatusPending PhaseStatus = "PENDING"
	StatusRunning PhaseStatus = "RUNNING"
	StatusDone    PhaseStatus = "DONE"
	StatusSkipped PhaseStatus = "SKIPPED"
	StatusFailed  PhaseStatus = "FAILED"
)

type URLState struct {
	URL         string
	Index       int
	Phase       string
	Status      PhaseStatus
	ParamFile   string
	PassiveFile string // sniper mode: final path of <domain>.passive inside outputDir
	X9Output    string
	PhaseStart  time.Time
	PhaseDur    time.Duration
	TotalDur    time.Duration
	StartTime   time.Time
	Findings    int
	mu          sync.Mutex
}

// ── Globals ───────────────────────────────────────────────────────────────────

var (
	outputDir      string
	nucleiTemplate string
	concurrency    int
	workers        int
	verbose        bool
	pipelineStart  time.Time
	mu             sync.Mutex
	totalVulns     int
	totalDone      int
	tg             *Telegram
	envBotToken    string
	envChatID      string
	silent         bool
	proxyURL       string
	mode           string // "cluster" | "sniper"
)

// ── Helpers ───────────────────────────────────────────────────────────────────
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, path[2:])
		}
	}
	return path
}

func stripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAllString(str, "")
}

func fmtDur(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func sanitize(rawURL string) string {
	re := regexp.MustCompile(`https?://`)
	s := re.ReplaceAllString(rawURL, "")
	re2 := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	s = re2.ReplaceAllString(s, "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.Trim(s, "-")
}

// extractHostname parses a raw URL and returns the bare hostname (no port, no scheme).
// For http://email.prod.asda.co.uk the result is "email.prod.asda.co.uk".
func extractHostname(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", rawURL, err)
	}
	host := u.Hostname() // strips port if present
	if host == "" {
		return "", fmt.Errorf("could not extract hostname from %q", rawURL)
	}
	return host, nil
}

// moveFile renames src to dst.  When src and dst are on different filesystems
// os.Rename fails with EXDEV; in that case we fall back to copy + remove.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// cross-device fallback
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("move open src: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("move create dst: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("move copy: %w", err)
	}
	out.Close()
	in.Close()
	return os.Remove(src)
}

// getBaseURL extracts the clean endpoint without query parameters from a Nuclei output line.
func getBaseURL(line string) string {
	fields := strings.Fields(line)
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			if idx := strings.Index(f, "?"); idx != -1 {
				return f[:idx]
			}
			return f
		}
	}
	return line
}

// ── Logging ───────────────────────────────────────────────────────────────────

func logLine(level, color, format string, args ...interface{}) {
	if silent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", gray, ts, reset, color, level, reset, msg)
}

func logCmd(cmd string) {
	if silent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[CMD]%s %s\n", gray, ts, reset, purple, reset, cmd)
}

func logPhaseHeader(idx, total int, targetURL string) {
	if silent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\n%s%s[%d/%d]%s %s%s%s\n",
		bold, cyan, idx, total, reset,
		white, targetURL, reset)
	fmt.Printf("%s%s%s\n", gray, strings.Repeat("─", 60), reset)
}

// ── Banner ────────────────────────────────────────────────────────────────────

func printBanner() {
	if silent {
		return
	}

	modeLabel := strings.ToUpper(mode)
	modeColor := blue
	pipeline := "nice_params → x9 → nuclei"
	if mode == "sniper" {
		modeColor = yellow
		pipeline = "nice_passive → nice_params → x9 → nuclei"
	}

	fmt.Printf("\n%s%s", bold, cyan)
	fmt.Println("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗")
	fmt.Println("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║")
	fmt.Println("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║")
	fmt.Println("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║")
	fmt.Println("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║")
	fmt.Println("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝")
	fmt.Printf("%s", reset)
	fmt.Printf("  %sXSS Pipeline%s  %s\n", yellow, reset, pipeline)
	fmt.Printf("  Mode: %s%s%s%s\n", bold, modeColor, modeLabel, reset)
	fmt.Printf("  %s%s%s\n\n", gray, strings.Repeat("─", 50), reset)
}

// ── Command runner ────────────────────────────────────────────────────────────

func runPhase(label, cmdStr string) (string, error) {
	logCmd(cmdStr)
	start := time.Now()

	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	if strings.Contains(cmdStr, "|") {
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		dur := time.Since(start)
		if err != nil {
			logLine("WARN", yellow, "%s failed after %s: %v", label, fmtDur(dur), err)
			return string(out), err
		}
		logLine("OK", green, "%s done in %s%s%s", label, bold, fmtDur(dur), reset)
		return string(out), nil
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	dur := time.Since(start)
	if err != nil {
		logLine("WARN", yellow, "%s failed after %s: %v", label, fmtDur(dur), err)
		return string(out), err
	}
	logLine("OK", green, "%s done in %s%s%s", label, bold, fmtDur(dur), reset)
	return string(out), nil
}

// ── Shared nuclei phase (used by both modes) ──────────────────────────────────

// runNuclei executes the nuclei XSS scan against x9Output and handles findings.
// phaseLabel is the "N/N" prefix shown in the PHASE log line (e.g. "3/3" or "4/4").
func runNuclei(state *URLState, x9Output, phaseLabel string) {
	state.mu.Lock()
	state.Phase = "nuclei"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	logLine("PHASE", green, "%s  nuclei xss scan", phaseLabel)
	nucleiCmd := fmt.Sprintf("cat %s | nuclei -t %s -silent", x9Output, nucleiTemplate)
	findings, _ := runPhase("nuclei", nucleiCmd)

	if strings.TrimSpace(findings) == "" {
		logLine("INFO", gray, "no findings for this URL")
		return
	}

	lines := strings.Split(strings.TrimSpace(findings), "\n")
	var clean []string
	seenEndpoints := make(map[string]bool)

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "[WRN]") || strings.HasPrefix(l, "[INF]") || strings.HasPrefix(l, "[ERR]") {
			continue
		}
		if !strings.Contains(l, "x9-reflection-only") {
			continue
		}

		baseEndpoint := getBaseURL(l)
		if seenEndpoints[baseEndpoint] {
			continue
		}
		seenEndpoints[baseEndpoint] = true
		clean = append(clean, l)
	}

	if len(clean) == 0 {
		logLine("INFO", gray, "no unique findings for this URL")
		return
	}

	state.Findings = len(clean)
	mu.Lock()
	totalVulns += len(clean)
	mu.Unlock()

	logLine("VULN", red, "⚠  %d unique finding(s) detected!", len(clean))
	for _, l := range clean {
		logLine("VULN", red, "  %s", l)
	}

	// فراخوانی متد نوتیفیکیشن تلگرام با هندلر بک‌آپ جدید
	tg.notify(state.URL, clean)

	// ذخیره در فایل یافته‌ها
	f, err := os.OpenFile(filepath.Join(outputDir, "findings.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintf(f, "\n[%s] URL: %s\n%s\n", time.Now().Format("2006-01-02 15:04:05"), state.URL, strings.Join(clean, "\n"))
		f.Close()
	}
}

// ── Mode: cluster (legacy, untouched pipeline) ────────────────────────────────

func processClusterURL(state *URLState, total int, wordlist string) {
	logPhaseHeader(state.Index, total, state.URL)
	state.StartTime = time.Now()
	safe := sanitize(state.URL)

	// ── Phase 1: nice_params ──────────────────────────────
	state.mu.Lock()
	state.Phase = "nice_params"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	paramFile := filepath.Join(outputDir, safe+"-params.txt")
	state.ParamFile = paramFile

	logLine("PHASE", purple, "1/3  nice_params")
	niceCmd := fmt.Sprintf("nice_params -w %s -u %s", wordlist, state.URL)
	out1, err1 := runPhase("nice_params", niceCmd)

	if err1 == nil && out1 != "" {
		if err := os.WriteFile(paramFile, []byte(out1), 0644); err != nil {
			logLine("ERR", red, "could not write param file: %v", err)
		}
	}

	fi, statErr := os.Stat(paramFile)
	if statErr != nil || fi.Size() == 0 {
		logLine("SKIP", yellow, "no params found — skipping x9 & nuclei for this URL")
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// ── Phase 2: x9 ───────────────────────────────────────
	state.mu.Lock()
	state.Phase = "x9"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	x9Output := filepath.Join(outputDir, safe+"-x9.txt")
	state.X9Output = x9Output

	logLine("PHASE", blue, "2/3  x9")
	x9Cmd := fmt.Sprintf("x9 -p %s -u %s -c %d", paramFile, state.URL, concurrency)
	_, err2 := runPhase("x9", x9Cmd)

	if _, err := os.Stat("x9_output.txt"); err == nil {
		if err := os.Rename("x9_output.txt", x9Output); err != nil {
			logLine("WARN", yellow, "could not rename x9_output.txt: %v", err)
		} else {
			logLine("INFO", cyan, "saved: %s", x9Output)
		}
	} else if err2 == nil {
		logLine("WARN", yellow, "x9_output.txt not found after x9 run")
	}

	fi2, statErr2 := os.Stat(x9Output)
	if statErr2 != nil || fi2.Size() == 0 {
		logLine("SKIP", yellow, "x9 output empty — skipping nuclei")
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// ── Phase 3: nuclei ───────────────────────────────────
	runNuclei(state, x9Output, "3/3")

	state.mu.Lock()
	state.Status = StatusDone
	state.TotalDur = time.Since(state.StartTime)
	state.mu.Unlock()

	mu.Lock()
	totalDone++
	elapsed := time.Since(pipelineStart)
	done := totalDone
	mu.Unlock()

	logLine("DONE", green, "URL complete in %s%s%s | elapsed: %s | done: %d/%d | vulns: %d",
		bold, fmtDur(state.TotalDur), reset,
		fmtDur(elapsed), done, total, totalVulns)
}

// ── Mode: sniper (passive crawl → params → x9 -i → nuclei) ───────────────────

func processSniperURL(state *URLState, total int, wordlist string) {
	logPhaseHeader(state.Index, total, state.URL)
	state.StartTime = time.Now()
	safe := sanitize(state.URL)

	// ── Phase 1: nice_passive (Step A) ────────────────────
	state.mu.Lock()
	state.Phase = "nice_passive"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	hostname, err := extractHostname(state.URL)
	if err != nil {
		logLine("WARN", yellow, "could not extract hostname from %q: %v — skipping", state.URL, err)
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// nice_passive writes <hostname>.passive into the current working directory.
	passiveCWD := hostname + ".passive"
	passiveDst := filepath.Join(outputDir, passiveCWD)

	logLine("PHASE", yellow, "1/4  nice_passive")
	passiveCmd := fmt.Sprintf("python3 /home/arian/MyBashs/nice_passive.py -d %s", hostname)
	_, passiveErr := runPhase("nice_passive", passiveCmd)

	if passiveErr != nil {
		logLine("WARN", yellow, "nice_passive failed for %s: %v — skipping", state.URL, passiveErr)
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	fi0, statErr0 := os.Stat(passiveCWD)
	if statErr0 != nil || fi0.Size() == 0 {
		logLine("WARN", yellow, "passive file %q missing or empty — skipping x9 & nuclei", passiveCWD)
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// Move passive file into outputDir so the working directory stays clean.
	// moveFile handles cross-device scenarios gracefully (copy + remove fallback).
	// Move passive file into outputDir so the working directory stays clean.
	// moveFile handles cross-device scenarios gracefully (copy + remove fallback).
	if err := moveFile(passiveCWD, passiveDst); err != nil {
		logLine("WARN", yellow, "could not move passive file to output dir: %v — skipping", err)
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}
	state.PassiveFile = passiveDst
	logLine("INFO", cyan, "passive file → %s", passiveDst)

	// ─── کدی که باید الان اضافه کنی (شروع) ───
	// اضافه کردن URL اصلی به فایل پسیو تا مطمئن شویم لوکال‌هاست یا مسیرهای خاص تست می‌شوند
	fAppend, errAppend := os.OpenFile(passiveDst, os.O_APPEND|os.O_WRONLY, 0644)
	if errAppend == nil {
		fAppend.WriteString(state.URL + "\n")
		fAppend.Close()
	} else {
		logLine("WARN", yellow, "could not append original URL to passive file: %v", errAppend)
	}
	// ─── کدی که باید الان اضافه کنی (پایان) ───

	// ── Phase 2: nice_params (Step B) ─────────────────────
	state.mu.Lock()
	state.Phase = "nice_params"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	paramFile := filepath.Join(outputDir, safe+"-params.txt")
	state.ParamFile = paramFile

	logLine("PHASE", purple, "2/4  nice_params")
	niceCmd := fmt.Sprintf("nice_params -w %s -u %s", wordlist, state.URL)
	out2, err2 := runPhase("nice_params", niceCmd)

	if err2 == nil && out2 != "" {
		if err := os.WriteFile(paramFile, []byte(out2), 0644); err != nil {
			logLine("ERR", red, "could not write param file: %v", err)
		}
	}

	fi1, statErr1 := os.Stat(paramFile)
	if statErr1 != nil || fi1.Size() == 0 {
		logLine("SKIP", yellow, "no params found — skipping x9 & nuclei for this URL")
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// ── Phase 3: x9 with -i (passive input) (Step C) ──────
	state.mu.Lock()
	state.Phase = "x9"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	x9Output := filepath.Join(outputDir, safe+"-x9.txt")
	state.X9Output = x9Output

	// In sniper mode x9 receives the passive URL list via -i instead of a single -u.
	logLine("PHASE", blue, "3/4  x9  (passive input)")
	x9Cmd := fmt.Sprintf("x9 -i %s -p %s -c %d", passiveDst, paramFile, concurrency)
	_, err3 := runPhase("x9", x9Cmd)

	if _, err := os.Stat("x9_output.txt"); err == nil {
		if err := os.Rename("x9_output.txt", x9Output); err != nil {
			logLine("WARN", yellow, "could not rename x9_output.txt: %v", err)
		} else {
			logLine("INFO", cyan, "saved: %s", x9Output)
		}
	} else if err3 == nil {
		logLine("WARN", yellow, "x9_output.txt not found after x9 run")
	}

	fi2, statErr2 := os.Stat(x9Output)
	if statErr2 != nil || fi2.Size() == 0 {
		logLine("SKIP", yellow, "x9 output empty — skipping nuclei")
		state.mu.Lock()
		state.Status = StatusSkipped
		state.TotalDur = time.Since(state.StartTime)
		state.mu.Unlock()
		mu.Lock()
		totalDone++
		mu.Unlock()
		return
	}

	// ── Phase 4: nuclei (Step D) ──────────────────────────
	runNuclei(state, x9Output, "4/4")

	state.mu.Lock()
	state.Status = StatusDone
	state.TotalDur = time.Since(state.StartTime)
	state.mu.Unlock()

	mu.Lock()
	totalDone++
	elapsed := time.Since(pipelineStart)
	done := totalDone
	mu.Unlock()

	logLine("DONE", green, "URL complete in %s%s%s | elapsed: %s | done: %d/%d | vulns: %d",
		bold, fmtDur(state.TotalDur), reset,
		fmtDur(elapsed), done, total, totalVulns)
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

func processURL(state *URLState, total int, wordlist string) {
	if mode == "sniper" {
		processSniperURL(state, total, wordlist)
	} else {
		processClusterURL(state, total, wordlist)
	}
}

// ── Summary ───────────────────────────────────────────────────────────────────

func printSummary(states []*URLState) {
	if silent {
		return
	}
	elapsed := time.Since(pipelineStart)
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\n%s%s%s\n", bold, strings.Repeat("═", 60), reset)
	fmt.Printf("  %s%sPipeline Complete%s\n", bold, green, reset)
	fmt.Printf("  %s%s%s\n\n", gray, strings.Repeat("─", 40), reset)

	done, skipped, failed := 0, 0, 0
	for _, s := range states {
		switch s.Status {
		case StatusDone:
			done++
		case StatusSkipped:
			skipped++
		case StatusFailed:
			failed++
		}
	}

	fmt.Printf("  %-20s %s%d%s\n", "URLs scanned:", bold, len(states), reset)
	fmt.Printf("  %-20s %s%d%s\n", "Completed:", bold, done, reset)
	fmt.Printf("  %-20s %s%s%d%s%s\n", "Skipped:", yellow, bold, skipped, reset, reset)
	fmt.Printf("  %-20s %s%s%d%s%s\n", "Failed:", red, bold, failed, reset, reset)
	if totalVulns > 0 {
		fmt.Printf("  %-20s %s%s⚠  %d%s%s\n", "Unique Findings:", red, bold, totalVulns, reset, reset)
	} else {
		fmt.Printf("  %-20s %s0%s\n", "Findings:", bold, reset)
	}
	fmt.Printf("  %-20s %s%s%s\n", "Total time:", bold, fmtDur(elapsed), reset)
	fmt.Printf("  %-20s %s%s%s\n", "Output dir:", cyan, outputDir, reset)
	if totalVulns > 0 {
		fmt.Printf("  %-20s %s%s/findings.txt%s\n", "Findings file:", cyan, outputDir, reset)
	}
	fmt.Printf("%s%s%s\n\n", bold, strings.Repeat("═", 60), reset)
}

// ── URL reader ────────────────────────────────────────────────────────────────

func readURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
			urls = append(urls, line)
		}
	}
	return urls, sc.Err()
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	urlFile := flag.String("l", "", "file containing URLs (one per line)")
	flag.StringVar(&outputDir, "o", "./pipeline_output", "output directory")
	flag.StringVar(&nucleiTemplate, "t", "~/applications/x9/xss_template.yaml", "nuclei template path")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency (-c flag passed to x9)")
	flag.IntVar(&workers, "w", 1, "parallel URL workers (default: 1 = sequential)")
	wordlist := flag.String("wl", "~/wordlist/params.txt", "wordlist path for nice_params -w")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&silent, "silent", false, "disable terminal output")
	flag.StringVar(&proxyURL, "proxy", "http://127.0.0.1:10808", "proxy url or off")
	flag.StringVar(&mode, "mode", "cluster", "pipeline mode: cluster (legacy) or sniper (passive crawl)")
	flag.Parse()
	*wordlist = expandPath(*wordlist)
	nucleiTemplate = expandPath(nucleiTemplate)
	outputDir = expandPath(outputDir)

	// Validate mode before anything else.
	if mode != "cluster" && mode != "sniper" {
		fmt.Printf("%s[!]%s invalid -mode %q — must be 'cluster' or 'sniper'\n", red, reset, mode)
		os.Exit(1)
	}

	printBanner()
	loadEnv()
	tg = newTelegram()
	if tg != nil {
		logLine("TG", cyan, "telegram notifications enabled (chat: %s)", tg.ChatID)
	} else {
		logLine("TG", yellow, "telegram disabled — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable")
	}

	if *urlFile == "" {
		fmt.Printf("%s[!]%s usage: recon_pipeline -l urls.txt [options]\n\n", red, reset)
		fmt.Println("  Options:")
		fmt.Println("    -l  <file>     URL list file (required)")
		fmt.Println("    -o  <dir>      output directory (default: ./pipeline_output)")
		fmt.Println("    -t  <path>     nuclei template (default: ~/applications/x9/xss_template.yaml)")
		fmt.Println("    -c  <int>      x9 concurrency (default: 10)")
		fmt.Println("    -w  <int>      parallel URL workers (default: 1)")
		fmt.Println("    -wl <path>     wordlist for nice_params (default: ~/wordlist/params.txt)")
		fmt.Println("    -mode <mode>   pipeline mode: cluster | sniper (default: cluster)")
		fmt.Println("    -silent        silence all terminal output")
		fmt.Println("    -proxy <url>   proxy url or 'off'")
		os.Exit(1)
	}

	urls, err := readURLs(*urlFile)
	if err != nil {
		fmt.Printf("%s[!]%s cannot read file: %v\n", red, reset, err)
		os.Exit(1)
	}
	if len(urls) == 0 {
		fmt.Printf("%s[!]%s no valid URLs found in %s\n", red, reset, *urlFile)
		os.Exit(1)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%s[!]%s cannot create output dir: %v\n", red, reset, err)
		os.Exit(1)
	}

	logLine("INFO", cyan, "mode: %s%s%s", bold, strings.ToUpper(mode), reset)
	logLine("INFO", cyan, "loaded %d URLs from %s", len(urls), *urlFile)
	logLine("INFO", cyan, "output dir: %s", outputDir)
	logLine("INFO", cyan, "wordlist: %s", *wordlist)
	logLine("INFO", cyan, "workers: %d | x9 concurrency: %d", workers, concurrency)

	states := make([]*URLState, len(urls))
	for i, u := range urls {
		states[i] = &URLState{
			URL:    u,
			Index:  i + 1,
			Status: StatusPending,
		}
	}

	pipelineStart = time.Now()

	if workers <= 1 {
		for _, s := range states {
			processURL(s, len(urls), *wordlist)
		}
	} else {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, s := range states {
			wg.Add(1)
			sem <- struct{}{}
			go func(st *URLState) {
				defer wg.Done()
				defer func() { <-sem }()
				processURL(st, len(urls), *wordlist)
			}(s)
		}
		wg.Wait()
	}

	printSummary(states)
}
