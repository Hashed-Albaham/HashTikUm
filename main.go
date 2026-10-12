package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	listenPort = getEnv("PORT", "8080")
	umProto    = getEnv("UM_PROTO", "http")
	umHost     = getEnv("UM_HOST", "192.168.216.1")
	umPort     = getEnv("UM_PORT", "12008")

	rawTargetURL  = os.Getenv("UM_TARGET_URL")
	targetBaseURL string
)

func init() {
	if rawTargetURL != "" {
		targetBaseURL = strings.TrimRight(rawTargetURL, "/")
	} else {
		proto := strings.ToLower(strings.TrimSuffix(umProto, "://"))
		host := strings.Trim(umHost, "/")
		targetBaseURL = fmt.Sprintf("%s://%s:%s", proto, host, umPort)
	}
}

type UserInfoResp struct {
	Success bool `json:"success"`
	Data    struct {
		Username    string `json:"username"`
		Upload      string `json:"upload"`
		Download    string `json:"download"`
		Uptime      string `json:"uptime"`
		ActiveSess  int    `json:"activeSess"`
		SharedUsers int    `json:"sharedUsers"`
	} `json:"data"`
}

type UserProfilesResp struct {
	Success bool `json:"success"`
	Data    struct {
		Profiles []struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			ProfileID int    `json:"profileId"`
			State     int    `json:"state"`
			ExpAfter  string `json:"expAfter"`
		} `json:"profiles"`
	} `json:"data"`
}

type UnifiedResponse struct {
	Success      bool           `json:"success"`
	MaskedUser   string         `json:"masked_username"`
	TimeLeft     string         `json:"time_left"`
	TotalTime    string         `json:"total_time"`
	DataLeft     string         `json:"data_left"`
	TotalData    string         `json:"total_data"`
	UsedDownload string         `json:"used_download"`
	UsedUpload   string         `json:"used_upload"`
	UsedUptime   string         `json:"used_uptime"`
	RemainVal    string         `json:"remaining_validity"`
	ProfileState string         `json:"profile_state"`
	Sessions     SessionDetails `json:"sessions"`
	RawProfile   string         `json:"profile_name"`
	Error        string         `json:"error,omitempty"`
}

type SessionDetails struct {
	ActiveSessions int `json:"active_sessions"`
	SharedUsers    int `json:"shared_users"`
}

func parseToBytes(str string) float64 {
	str = strings.ToUpper(strings.ReplaceAll(str, ",", ""))
	re := regexp.MustCompile(`([\d\.]+)\s*([KMGTP]?)`)
	match := re.FindStringSubmatch(str)
	if len(match) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0
	}
	unit := ""
	if len(match) > 2 {
		unit = match[2]
	}
	switch unit {
	case "K":
		return val * 1024
	case "M":
		return val * 1048576
	case "G":
		return val * 1073741824
	case "T":
		return val * 1099511627776
	default:
		return val
	}
}

func formatBytes(bytes float64) string {
	if bytes <= 0 || math.IsNaN(bytes) {
		return "0 B"
	}
	sizes := []string{"B", "KB", "MB", "GB", "TB"}
	i := int(math.Floor(math.Log(bytes) / math.Log(1024)))
	if i < 0 {
		i = 0
	}
	if i >= len(sizes) {
		i = len(sizes) - 1
	}
	return fmt.Sprintf("%.2f %s", bytes/math.Pow(1024, float64(i)), sizes[i])
}

func parseToSeconds(str string) int64 {
	re := regexp.MustCompile(`(?i)(\d+)([wdhms])`)
	matches := re.FindAllStringSubmatch(str, -1)
	var total int64
	for _, m := range matches {
		val, _ := strconv.ParseInt(m[1], 10, 64)
		unit := strings.ToLower(m[2])
		switch unit {
		case "w":
			total += val * 604800
		case "d":
			total += val * 86400
		case "h":
			total += val * 3600
		case "m":
			total += val * 60
		case "s":
			total += val
		}
	}
	return total
}

func formatSeconds(sec int64) string {
	if sec <= 0 {
		return "0m"
	}
	w := sec / 604800
	d := (sec % 604800) / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60

	var res []string
	if w > 0 {
		res = append(res, fmt.Sprintf("%dw", w))
	}
	if d > 0 {
		res = append(res, fmt.Sprintf("%dd", d))
	}
	if h > 0 {
		res = append(res, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		res = append(res, fmt.Sprintf("%dm", m))
	}
	if len(res) == 0 {
		return "< 1m"
	}
	return strings.Join(res, " ")
}

func maskUsername(user string) string {
	if len(user) <= 4 {
		return "****"
	}
	return user[:2] + strings.Repeat("*", len(user)-4) + user[len(user)-2:]
}

func parseProfileConfig(name string) (string, string) {
	totalData, totalTime := "unlimited", "unlimited"
	parts := strings.Split(strings.TrimSpace(name), "-")
	if len(parts) >= 3 {
		t := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
		d := strings.ToUpper(strings.TrimSpace(parts[len(parts)-2]))
		if !strings.Contains(t, "un") {
			totalTime = t
		}
		if !strings.Contains(strings.ToLower(d), "un") {
			totalData = d
		}
	}
	return totalData, totalTime
}

func handleQuery(w http.ResponseWriter, r *http.Request) {
	// إتاحة الـ CORS لصفحة الهوتسبوت
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	username := r.URL.Query().Get("user")
	password := r.URL.Query().Get("pass")
	if username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(UnifiedResponse{Success: false, Error: "Username is required (?user=...)"})
		return
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	loginData := url.Values{}
	loginData.Set("username", username)
	loginData.Set("password", password)

	loginResp, err := client.PostForm(targetBaseURL+"/um/api/login", loginData)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(UnifiedResponse{Success: false, Error: "UM Gateway Unreachable: " + err.Error()})
		return
	}
	defer loginResp.Body.Close()

	var loginResult struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(loginResp.Body).Decode(&loginResult)
	if !loginResult.Success {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(UnifiedResponse{Success: false, Error: "Invalid credentials"})
		return
	}

	var wg sync.WaitGroup
	var uInfo UserInfoResp
	var uProfs UserProfilesResp

	wg.Add(2)
	go func() {
		defer wg.Done()
		res, err := client.Get(targetBaseURL + "/um/api/getUser")
		if err == nil {
			defer res.Body.Close()
			json.NewDecoder(res.Body).Decode(&uInfo)
		}
	}()
	go func() {
		defer wg.Done()
		res, err := client.Get(targetBaseURL + "/um/api/getUserProfiles")
		if err == nil {
			defer res.Body.Close()
			json.NewDecoder(res.Body).Decode(&uProfs)
		}
	}()
	wg.Wait()

	usedDataBytes := parseToBytes(uInfo.Data.Download) + parseToBytes(uInfo.Data.Upload)
	usedTimeSec := parseToSeconds(uInfo.Data.Uptime)

	activeProfName := ""
	stateStr := "Unknown"
	remainVal := "..."

	if len(uProfs.Data.Profiles) > 0 {
		active := uProfs.Data.Profiles[0]
		activeProfName = active.Name
		if active.State == 3 {
			stateStr = "Expired"
			remainVal = "Used/Expired"
		} else {
			stateStr = "Active"
			remainVal = active.ExpAfter
		}
	}

	confData, confTime := parseProfileConfig(activeProfName)
	dataLeftStr := "unlimited"
	dataTotalStr := "unlimited"
	timeLeftStr := "unlimited"
	timeTotalStr := "unlimited"

	if confData != "unlimited" {
		totalBytes := parseToBytes(confData)
		diff := totalBytes - usedDataBytes
		if diff < 0 {
			diff = 0
		}
		dataLeftStr = formatBytes(diff)
		dataTotalStr = confData
	}

	if confTime != "unlimited" {
		totalSec := parseToSeconds(confTime)
		diff := totalSec - usedTimeSec
		if diff < 0 {
			diff = 0
		}
		timeLeftStr = formatSeconds(diff)
		timeTotalStr = formatSeconds(totalSec)
	}

	output := UnifiedResponse{
		Success:      true,
		MaskedUser:   maskUsername(username),
		TimeLeft:     timeLeftStr,
		TotalTime:    timeTotalStr,
		DataLeft:     dataLeftStr,
		TotalData:    dataTotalStr,
		UsedDownload: uInfo.Data.Download,
		UsedUpload:   uInfo.Data.Upload,
		UsedUptime:   uInfo.Data.Uptime,
		RemainVal:    remainVal,
		ProfileState: stateStr,
		Sessions: SessionDetails{
			ActiveSessions: uInfo.Data.ActiveSess,
			SharedUsers:    uInfo.Data.SharedUsers,
		},
		RawProfile: activeProfName,
	}

	json.NewEncoder(w).Encode(output)
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func main() {
	http.HandleFunc("/api/user-status", handleQuery)
	log.Printf("Proxy service started on port %s", listenPort)
	log.Printf("Connecting to User Manager at: %s", targetBaseURL)

	if err := http.ListenAndServe(":"+listenPort, nil); err != nil {
		log.Fatalf("Server stopped: %v", err)
	}
}
