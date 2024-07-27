package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const N = "200"
const TYPE = "1"
const ENC = "srun_bx1"

// basic info
var action string
var username string
var password string
var ip = ""
var loginUrl = "https://net.zju.edu.cn"

// login params
var ac_id string
var randNumStr string

func main() {

	flag.StringVar(&action, "a", "login", "login or logout or hold")
	flag.StringVar(&username, "u", "", "username")
	flag.StringVar(&password, "p", "", "password")
	flag.StringVar(&ip, "i", "", "ip")
	flag.StringVar(&loginUrl, "l", "https://net.zju.edu.cn", "url")
	flag.Parse()
	fmt.Println("action:", action, "username:", username, "password:", password, "ip:", ip, "url:", loginUrl)
	if action != "login" && action != "logout" && action != "hold" {
		fmt.Println("action must be login or logout or hold.Use -h to get help.")
		return
	}
	if username == "" {
		fmt.Println("username is required.Use -h to get help.")
		return
	}
	if password == "" {
		fmt.Println("password is required.Use -h to get help.")
		return
	}
	if len(loginUrl) > 1 && loginUrl[len(loginUrl)-1] == '/' {
		loginUrl = loginUrl[:len(loginUrl)-1]
	}

	baseUrl, err := url.Parse(loginUrl)
	if err != nil {
		panic(err)
	}

	initUrl := baseUrl.ResolveReference(&url.URL{Path: "/"})
	getChallengeApi := baseUrl.ResolveReference(&url.URL{Path: "/cgi-bin/get_challenge"})
	srunPortalApi := baseUrl.ResolveReference(&url.URL{Path: "/cgi-bin/srun_portal"})
	radUserDmApi := baseUrl.ResolveReference(&url.URL{Path: "/cgi-bin/rad_user_dm"})

	fmt.Println("initUrl:", initUrl.String())
	fmt.Println("getChallengeApi:", getChallengeApi.String())
	fmt.Println("srunPortalApi:", srunPortalApi.String())
	fmt.Println("radUserDmApi:", radUserDmApi.String())

	client := &http.Client{}

	initConnection(client, initUrl)
	// Now you can use client to send HTTP requests
	// For example:
	//_, err = client.Get(initUrl.String())
	//if err != nil {
	//	panic(err)
	//}

}

func ordat(msg string, idx int) rune {
	runes := []rune(msg)
	if len(runes) > idx {
		return runes[idx]
	}
	return 0
}

func sencode(msg string, key bool) []int {
	l := len(msg)
	pwd := make([]int, 0, (l+3)/4+1)
	for i := 0; i < l; i += 4 {
		pwd = append(pwd, int(ordat(msg, i))|int(ordat(msg, i+1))<<8|int(ordat(msg, i+2))<<16|int(ordat(msg, i+3))<<24)
	}
	if key {
		pwd = append(pwd, l)
	}
	return pwd
}

func lencode(msg []int, key bool) string {
	l := len(msg)
	ll := (l - 1) << 2
	if key {
		m := msg[l-1]
		if m < ll-3 || m > ll {
			return ""
		}
		ll = m
	}
	result := ""
	for i := 0; i < l; i++ {
		result += fmt.Sprintf("%c", msg[i]&0xff) + fmt.Sprintf("%c", msg[i]>>8&0xff) + fmt.Sprintf("%c", msg[i]>>16&0xff) + fmt.Sprintf("%c", msg[i]>>24&0xff)
	}
	if key {
		return result[:ll]
	}
	return result
}

func get_xencode(msg string, key string) string {
	if msg == "" {
		return ""
	}
	pwd := sencode(msg, true)
	pwdk := sencode(key, false)
	if len(pwdk) < 4 {
		pwdk = append(pwdk, make([]int, 4-len(pwdk))...)
	}
	n := len(pwd) - 1
	z := pwd[n]
	c := 0x86014019 | 0x183639A0
	q := int(math.Floor(6 + 52/float64(n+1)))
	d := 0
	for q > 0 {
		d = (d + c) & (0x8CE0D9BF | 0x731F2640)
		e := d >> 2 & 3
		p := 0
		for p < n {
			y := pwd[p+1]
			m := (z >> 5) ^ (y << 2)
			m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
			m += pwdk[(p&3)^e] ^ z
			pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
			z = pwd[p]
			p++
		}
		y := pwd[0]
		m := (z >> 5) ^ (y << 2)
		m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
		m += pwdk[(p&3)^e] ^ z
		pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
		z = pwd[n]
		q--
	}
	return lencode(pwd, false)
}

func getBase64(s string) string {
	_ALPHA := "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	//_PADCHAR := "="
	var Encoder *base64.Encoding = base64.NewEncoding(_ALPHA)
	return Encoder.EncodeToString([]byte(s))
}

func getMD5(password, token string) string {
	key := []byte(token)
	message := []byte(password)

	// 创建一个新的 HMAC 使用 MD5 哈希算法
	mac := hmac.New(md5.New, key)
	mac.Write(message)

	// 计算出哈希值并转为十六进制字符串
	return hex.EncodeToString(mac.Sum(nil))
}

func getSha1(s string) string {
	//使用sha1哈希函数
	h := sha1.New()
	h.Write([]byte(s))
	//返回加密结果
	return hex.EncodeToString(h.Sum(nil))

}

func initConnection(client *http.Client, initUrl *url.URL) {
	fmt.Println("zju-web-login init")
	initRes, _ := client.Get(initUrl.String())
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(initRes.Body)
	body, err := io.ReadAll(initRes.Body)
	if err != nil {
		panic(err)
	}
	reAcID := regexp.MustCompile(`id="ac_id" value="(.*?)"`)
	reIP := regexp.MustCompile(`id="user_ip" value="(.*?)"`)

	initResText := string(body)
	acIDMatch := reAcID.FindStringSubmatch(initResText)
	ipMatch := reIP.FindStringSubmatch(initResText)

	//second element is the match
	if len(acIDMatch) < 2 {
		fmt.Println("acIDMatch error:", acIDMatch)
		return
	}
	ac_id = acIDMatch[1]
	if len(ipMatch) < 2 {
		fmt.Println("ipMatch error:", ipMatch)
		return
	}
	ip = ipMatch[1]

	//random number 1-1234567890123456789012
	// Define the range of the random number
	minRand := big.NewInt(1)
	maxRand := big.NewInt(1)
	maxRand.SetString("1234567890123456789012", 10)
	// Generate a random big.Int in [min, max)
	diff := new(big.Int).Sub(maxRand, minRand)
	randNum := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), diff)
	randNum.Add(randNum, minRand)
	// Convert the big.Int to a string
	randNumStr = randNum.String()

	fmt.Println("ac_id:", ac_id, "ip:", ip, "randNum:", randNumStr)
	fmt.Println("zju-web-login init success")

}
