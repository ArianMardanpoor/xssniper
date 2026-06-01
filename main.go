package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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

// ── Telegram ─────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

// loadEnv reads a .env file and sets any unset env variables from it.
// looks for .env next to the binary, then in current working directory.
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
	if proxyURL != "" && strings.ToLower(proxyURL) != "off" {
		if p, err := url.Parse(proxyURL); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func (tg *Telegram) send(text string) error {
	if tg == nil {
		return fmt.Errorf("telegram configuration is missing")
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.Token)
	payload := map[string]string{
		"chat_id":    tg.ChatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	body, _ := json.Marshal(payload)
	client := telegramClient()
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("telegram api returned status code %d", resp.StatusCode)
	}
	return nil
}

func (tg *Telegram) notify(targetURL string, findings []string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString("🚨 <b>XSS Finding!</b>\n\n")
	sb.WriteString(fmt.Sprintf("🎯 <b>URL:</b> <code>%s</code>\n", escapeHTML(targetURL)))
	sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n", ts))
	sb.WriteString(fmt.Sprintf("🔢 <b>Count:</b> %d unique endpoint(s)\n\n", len(findings)))
	sb.WriteString("<b>Details:</b>\n")
	for i, f := range findings {
		if f == "" {
			continue
		}
		line := f
		if len(line) > 200 {
			line = line[:200] + "…"
		}
		sb.WriteString(fmt.Sprintf("<code>%d. %s</code>\n", i+1, escapeHTML(line)))
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
			// ایجاد دایرکتوری در صورت عدم وجود
			if errMkdir := os.MkdirAll(logDir, 0755); errMkdir == nil {
				timestamp := time.Now().Format("20060102_150405")
				// استفاده از نانوثانیه برای جلوگیری از Overwrite همزمان واکشی‌ها
				logFile := filepath.Join(logDir, fmt.Sprintf("failed_notif_%s_%d.txt", timestamp, time.Now().Nanosecond()))

				logContent := fmt.Sprintf("FAILED TO SEND AT: %s\nREASON: %v\n-----------------------------------\n%s\n",
					time.Now().Format("2006-01-02 15:04:05"), sendErr, sb.String())

				if errWrite := os.WriteFile(logFile, []byte(logContent), 0644); errWrite == nil {
					logLine("INFO", cyan, "saved backup log to %s", logFile)
				} else {
					logLine("ERR", red, "could not write backup log file: %v", errWrite)
				}
			} else {
				logLine("ERR", red, "could not create backup log directory: %v", errMkdir)
			}
		} else {
			logLine("ERR", red, "could not get user home directory: %v", errHome)
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

// ANSI colors
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

type PhaseStatus string

const (
	StatusPending PhaseStatus = "PENDING"
	StatusRunning PhaseStatus = "RUNNING"
	StatusDone    PhaseStatus = "DONE"
	StatusSkipped PhaseStatus = "SKIPPED"
	StatusFailed  PhaseStatus = "FAILED"
)

type URLState struct {
	URL        string
	Index      int
	Phase      string
	Status     PhaseStatus
	ParamFile  string
	X9Output   string
	PhaseStart time.Time
	PhaseDur   time.Duration
	TotalDur   time.Duration
	StartTime  time.Time
	Findings   int
	mu         sync.Mutex
}

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
	silent         bool
	proxyURL       string
)

func fmtDur(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func sanitize(url string) string {
	re := regexp.MustCompile(`https?://`)
	s := re.ReplaceAllString(url, "")
	re2 := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	s = re2.ReplaceAllString(s, "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.Trim(s, "-")
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

func logPhaseHeader(idx, total int, url string) {
	if silent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\n%s%s[%d/%d]%s %s%s%s\n",
		bold, cyan, idx, total, reset,
		white, url, reset)
	fmt.Printf("%s%s%s\n", gray, strings.Repeat("─", 60), reset)
}

func printBanner() {
	if silent {
		return
	}
	fmt.Printf("\n%s%s", bold, cyan)
	fmt.Println("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗")
	fmt.Println("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║")
	fmt.Println("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║")
	fmt.Println("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║")
	fmt.Println("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║")
	fmt.Println("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝")
	fmt.Printf("%s", reset)
	fmt.Printf("  %sXSS Pipeline%s  nice_params → x9 → nuclei\n", yellow, reset)
	fmt.Printf("  %s%s%s\n\n", gray, strings.Repeat("─", 50), reset)
}

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

func processURL(state *URLState, total int, wordlist string) {
	logPhaseHeader(state.Index, total, state.URL)
	state.StartTime = time.Now()
	safe := sanitize(state.URL)

	// ── Phase 1: nice_params ─────────────────────────────
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

	// ── Phase 2: x9 ──────────────────────────────────────
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
	state.mu.Lock()
	state.Phase = "nuclei"
	state.PhaseStart = time.Now()
	state.mu.Unlock()

	logLine("PHASE", green, "3/3  nuclei xss scan")
	nucleiCmd := fmt.Sprintf("cat %s | nuclei -t %s -silent", x9Output, nucleiTemplate)
	findings, _ := runPhase("nuclei", nucleiCmd)

	if strings.TrimSpace(findings) != "" {
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

		if len(clean) > 0 {
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
		} else {
			logLine("INFO", gray, "no unique findings for this URL")
		}
	} else {
		logLine("INFO", gray, "no findings for this URL")
	}

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

func main() {
	urlFile := flag.String("l", "", "file containing URLs (one per line)")
	flag.StringVar(&outputDir, "o", "./pipeline_output", "output directory")
	flag.StringVar(&nucleiTemplate, "t", "~/applications/x9/xss_template.yaml", "nuclei template path")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency (-c flag passed to x9)")
	flag.IntVar(&workers, "w", 1, "parallel URL workers (default: 1 = sequential)")
	wordlist := flag.String("wl", "~/wordlist/top_xss_params.txt", "wordlist path for nice_params -p")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&silent, "silent", false, "disable terminal output")
	flag.StringVar(&proxyURL, "proxy", "", "proxy url or off")
	flag.Parse()

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
		fmt.Println("    -l  <file>   URL list file (required)")
		fmt.Println("    -o  <dir>    output directory (default: ./pipeline_output)")
		fmt.Println("    -t  <path>   nuclei template (default: ~/applications/x9/xss_template.yaml)")
		fmt.Println("    -c  <int>    x9 concurrency (default: 10)")
		fmt.Println("    -w  <int>    parallel URL workers (default: 1)")
		fmt.Println("    -silent      Silent the whole procces")
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

	logLine("INFO", cyan, "loaded %d URLs from %s", len(urls), *urlFile)
	logLine("INFO", cyan, "output dir: %s", outputDir)
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
