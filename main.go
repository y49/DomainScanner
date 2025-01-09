package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ------------------- 1. 规则字符集 (老式 logic: A/B/C/D) ------------------- //
var (
	lettersLower = []rune("abcdefghijklmnopqrstuvwxyz")           // A
	digits       = []rune("0123456789")                           // B
	lettersDigit = []rune("abcdefghijklmnopqrstuvwxyz0123456789") // C
)

func getRuneSet(ch rune) ([]rune, error) {
	switch ch {
	case 'A':
		return lettersLower, nil
	case 'B':
		return digits, nil
	case 'C':
		return lettersDigit, nil
	default:
		return nil, fmt.Errorf("unsupported pattern char: %c", ch)
	}
}

func generateDomainBodiesFromOldPattern(pattern string) ([]string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, errors.New("empty pattern")
	}
	var parts [][]rune
	for _, c := range pattern {
		set, err := getRuneSet(c)
		if err != nil {
			return nil, err
		}
		parts = append(parts, set)
	}
	var results []string
	var backtrack func(idx int, current []rune)
	backtrack = func(idx int, current []rune) {
		if idx == len(parts) {
			results = append(results, strings.ToLower(string(current)))
			return
		}
		for _, r := range parts[idx] {
			current[idx] = r
			backtrack(idx+1, current)
		}
	}
	current := make([]rune, len(parts))
	backtrack(0, current)
	return results, nil
}

// ------------------- 2. 更灵活的风格模式 ------------------- //
func generateDomainBodiesFromStyle(style string, allowedRunes []rune) ([]string, error) {
	style = strings.ToUpper(strings.TrimSpace(style))
	if style == "" {
		return nil, fmt.Errorf("style is empty")
	}
	// 收集 style 中的 distinct letter
	distinctMap := make(map[rune]struct{})
	for _, ch := range style {
		if ch < 'A' || ch > 'Z' {
			return nil, fmt.Errorf("invalid character in style: %c", ch)
		}
		distinctMap[ch] = struct{}{}
	}
	distinctLetters := make([]rune, 0, len(distinctMap))
	for k := range distinctMap {
		distinctLetters = append(distinctLetters, k)
	}
	sort.Slice(distinctLetters, func(i, j int) bool {
		return distinctLetters[i] < distinctLetters[j]
	})

	// 回溯
	letterAssignment := make(map[rune]rune, len(distinctLetters))
	var results []string

	var backtrack func(idx int)
	backtrack = func(idx int) {
		if idx == len(distinctLetters) {
			// 构造域名主体
			result := make([]rune, len(style))
			for i, ch := range style {
				result[i] = letterAssignment[ch]
			}
			results = append(results, strings.ToLower(string(result)))
			return
		}
		letter := distinctLetters[idx]
		for _, candidate := range allowedRunes {
			letterAssignment[letter] = candidate
			backtrack(idx + 1)
		}
	}
	backtrack(0)
	return results, nil
}

// ------------------- 3. 统一生成域名 ------------------- //
func generateAllDomains(mode string, patterns []string, suffixes []string) []string {
	domainSet := make(map[string]struct{})
	bigSet := []rune("abcdefghijklmnopqrstuvwxyz0123456789")

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var bodies []string
		var err error
		switch mode {
		case "old":
			bodies, err = generateDomainBodiesFromOldPattern(p)
		case "style":
			bodies, err = generateDomainBodiesFromStyle(p, bigSet)
		case "literal":
			// 直接 literal
			bodies = []string{strings.ToLower(p)}
		default:
			log.Printf("[WARN] unknown mode=%s, skip pattern=%s", mode, p)
			continue
		}
		if err != nil {
			log.Printf("[WARN] pattern=%s err=%v", p, err)
			continue
		}

		// 拼后缀
		for _, b := range bodies {
			for _, sfx := range suffixes {
				domainSet[b+sfx] = struct{}{}
			}
		}
	}

	results := make([]string, 0, len(domainSet))
	for d := range domainSet {
		results = append(results, d)
	}
	sort.Strings(results)
	return results
}

// ------------------- 4. WHOIS检查 & 并发逻辑 ------------------- //
var whoisServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"cn":   "whois.cnnic.cn",
	"top":  "whois.afilias-srs.net",
	"dev":  "whois.nic.google",
	"cc":   "ccwhois.verisign-grs.com",
	"xyz":  "whois.nic.xyz",
	"de":   "whois.denic.de",
	"info": "whois.afilias.net",
	"sbs":  "whois.nic.sbs",
	"in":   "whois.registry.in",
	"best": "whois.nic.best",
	"my":   "whois.mynic.my",
	"me":   "whois.nic.me",
	"ltd":  "whois.nic.ltd",
	"pro":  "whois.nic.pro",
	"live": "whois.nic.live",
	"art":  "whois.nic.art",
	"chat": "whois.nic.chat",
	"vip":  "whois.nic.vip",
	"link": "whois.uniregistry.net",
	"ren":  "whois.nic.ren",
}

func parseDomainSuffix(domain string) string {
	parts := strings.Split(domain, ".")
	return parts[len(parts)-1]
}

func whoisCheck(ctx context.Context, domain string) (bool, error) {
	suffix := parseDomainSuffix(domain)
	whoisServer, ok := whoisServers[suffix]
	if !ok {
		return false, fmt.Errorf("no whois server for suffix: %s", suffix)
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", whoisServer+":43")
	if err != nil {
		return false, fmt.Errorf("dial fail: %v", err)
	}
	defer conn.Close()

	query := domain + "\r\n"
	_, err = conn.Write([]byte(query))
	if err != nil {
		return false, fmt.Errorf("write fail: %v", err)
	}

	var lines []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return false, fmt.Errorf("read fail: %v", scanErr)
	}
	joined := strings.ToLower(strings.Join(lines, "\n"))
	// 判断是否可注册
	if strings.Contains(joined, "no match") ||
		strings.Contains(joined, "not found") ||
		strings.Contains(joined, "available") {
		return true, nil
	}
	return false, nil
}

// suffixesHandler: 基于 whoisServers 的 key 动态生成后缀列表
func suffixesHandler(w http.ResponseWriter, r *http.Request) {
	// 如果需要兼容 OPTIONS 预检请求
	if r.Method == http.MethodOptions {
		return
	}
	w.Header().Set("Content-Type", "application/json")

	// 1. 遍历 whoisServers 的 key，生成后缀 ".com"、".net"、".cn" 等
	var suffixes []string
	for key := range whoisServers {
		suffixes = append(suffixes, "."+key)
	}

	// 2. 排序一下(可选)
	sort.Strings(suffixes)

	// 3. 转为 JSON 数组返回
	data, _ := json.Marshal(suffixes)
	w.Write(data)
}

// 全局状态
var (
	allDomains  []string
	totalCount  int
	currentDone int

	scanning bool
	paused   bool

	wg       sync.WaitGroup
	stopChan chan struct{}
	mu       sync.Mutex

	availableList []string
	failedList    []string

	sseClients = struct {
		sync.Mutex
		chans map[chan string]bool
	}{
		chans: make(map[chan string]bool),
	}

	// 为了“暂停-继续”更优雅，可以使用 sync.Cond
	cond = sync.NewCond(&mu)
)

// SSE广播
func broadcast(msg string) {
	sseClients.Lock()
	defer sseClients.Unlock()
	for ch := range sseClients.chans {
		select {
		case ch <- msg:
		default:
		}
	}
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-cache")

	ch := make(chan string, 10)
	sseClients.Lock()
	sseClients.chans[ch] = true
	sseClients.Unlock()

	notify := w.(http.CloseNotifier).CloseNotify()
	go func() {
		<-notify
		sseClients.Lock()
		delete(sseClients.chans, ch)
		sseClients.Unlock()
	}()

	for {
		msg, ok := <-ch
		if !ok {
			return
		}
		parts := strings.SplitN(msg, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", parts[0], parts[1])
		} else {
			fmt.Fprintf(w, "data: %s\n\n", msg)
		}
		if f, ok2 := w.(http.Flusher); ok2 {
			f.Flush()
		}
	}
}

// ------------ worker: 核心部分，支持“暂停”而不退出 ------------
func worker(domainChan <-chan string, concurrencyTimeout time.Duration) {
	defer wg.Done()
	for {
		select {
		case <-stopChan:
			// 如果 stopChan 被关闭，则立即退出
			return
		case domain, ok := <-domainChan:
			if !ok {
				// 域名已经全部读取完
				return
			}

			// 如果处于 paused 状态，则阻塞等待
			mu.Lock()
			for paused {
				// 通过 cond.Wait() 让当前 worker 等待
				cond.Wait()
				// 等到 resume 时，外部会 cond.Broadcast() 唤醒
				// 如果这时发现 stopChan 已经关闭，则也要退出
				select {
				case <-stopChan:
					mu.Unlock()
					return
				default:
				}
			}
			mu.Unlock()

			// =============== 正式执行 Whois 检查 ===============
			ctx, cancel := context.WithTimeout(context.Background(), concurrencyTimeout)
			available, err := whoisCheck(ctx, domain)
			cancel()

			// 计数更新
			mu.Lock()
			currentDone++
			done := currentDone
			total := totalCount
			mu.Unlock()

			broadcast(fmt.Sprintf("scanned:[%d/%d] %s", done, total, domain))

			// 记录失败 / 成功 / 可用
			if err != nil {
				mu.Lock()
				failedList = append(failedList, domain)
				mu.Unlock()
				broadcast("fail:" + domain)
			} else if available {
				mu.Lock()
				availableList = append(availableList, domain)
				mu.Unlock()
				broadcast("available:" + domain)
			}
		}
	}
}

// ------------ start ------------
func startScan(concurrency int) {
	mu.Lock()
	scanning = true
	paused = false
	currentDone = 0
	totalCount = len(allDomains)
	availableList = nil
	failedList = nil
	mu.Unlock()

	stopChan = make(chan struct{})
	domainChan := make(chan string, 100)

	// 启动 N 个 worker
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(domainChan, 5*time.Second)
	}

	// 将所有域名投入 channel
	go func() {
		for _, d := range allDomains {
			domainChan <- d
		}
		close(domainChan)
	}()

	// 等待所有 worker 完成
	go func() {
		wg.Wait()
		mu.Lock()
		scanning = false
		paused = false
		mu.Unlock()
		broadcast("scanned:扫描结束！")
		log.Println("扫描结束!")
	}()
}

// ------------ pause：不再关闭 stopChan，而是仅设置 paused=true ------------
func pauseScan() {
	mu.Lock()
	if scanning && !paused {
		paused = true
		log.Println("扫描已暂停")
	}
	mu.Unlock()
}

// ------------ resume：将 paused=false 并唤醒 worker ------------
func resumeScan() {
	mu.Lock()
	if paused {
		paused = false
		cond.Broadcast() // 唤醒所有因 pause 而等待的 worker
		log.Println("扫描已继续")
	}
	mu.Unlock()
}

// ------------ stop：彻底结束扫描，关闭 stopChan ------------
func stopScan() {
	mu.Lock()
	if scanning || paused {
		scanning = false
		paused = false
		select {
		case <-stopChan:
			// stopChan 已经被关闭过了，无需再关
		default:
			close(stopChan)
		}
		cond.Broadcast() // 万一有 worker 在 pause 等待，也让它退出
		broadcast("scanned:扫描被终止！")
		log.Println("扫描已终止")
	}
	mu.Unlock()
}

// ------------ 各路由处理 ------------
func startHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	mode := r.FormValue("mode")
	patternStr := r.FormValue("patterns")
	suffixStr := r.FormValue("suffixes")
	concurrencyStr := r.FormValue("concurrency")

	concurrency := 5
	if concurrencyStr != "" {
		fmt.Sscanf(concurrencyStr, "%d", &concurrency)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	var patterns []string
	for _, p := range strings.Split(patternStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		patterns = []string{"AABB"}
	}

	var suffixes []string
	for _, s := range strings.Split(suffixStr, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			suffixes = append(suffixes, s)
		}
	}
	if len(suffixes) == 0 {
		suffixes = []string{".com"}
	}

	domains := generateAllDomains(mode, patterns, suffixes)
	mu.Lock()
	allDomains = domains
	mu.Unlock()

	log.Printf("开始扫描, mode=%s, 域名数量: %d, 并发: %d\n", mode, len(domains), concurrency)
	go startScan(concurrency)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func pauseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pauseScan()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func resumeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resumeScan()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func stopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stopScan()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	handleCORS := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				return
			}
			h.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/api/start", handleCORS(startHandler))
	http.HandleFunc("/api/pause", handleCORS(pauseHandler))
	http.HandleFunc("/api/resume", handleCORS(resumeHandler))
	http.HandleFunc("/api/stop", handleCORS(stopHandler))

	http.HandleFunc("/api/events", handleCORS(eventsHandler))

	http.HandleFunc("/api/suffixes", handleCORS(suffixesHandler))

	log.Println("服务器启动: http://127.0.0.1:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
