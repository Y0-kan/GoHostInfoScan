package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"github.com/Y0-kan/GoHostInfoScan/nmapIPRange"
	"time"
)

const (
	TIME_OUT = 3 * time.Second
)

var length = 0

func attributeName(Target_Info_bytes []byte) string {
	att_name_length := binary.LittleEndian.Uint16(Target_Info_bytes[length+2 : length+4])
	att_name := bytes.ReplaceAll(Target_Info_bytes[length+4:length+4+int(att_name_length)], []byte{0x00}, []byte{})
	length = length + 4 + int(att_name_length)
	return string(att_name)
}

func sendPacket(ip string) string {
	conn, err := net.DialTimeout("tcp", ip+":135", TIME_OUT)
	if err != nil {
		// fmt.Println(err)
		return "-1"
	}
	defer conn.Close()

	buffer_v1 := []byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa, 0x03, 0x00, 0x00, 0x00, 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36, 0x01, 0x00, 0x00, 0x00}
	conn.SetWriteDeadline(time.Now().Add(TIME_OUT))
	_, err = conn.Write(buffer_v1)
	if err != nil {
		return "-1"
	}

	packet1 := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(TIME_OUT))
	_, err = conn.Read(packet1)
	if err != nil {
		return "-1"
	}

	digit := "x86"
	if bytes.Contains(packet1, []byte{0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49, 0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36}) {
		digit = "x64"
	}

	//fmt.Println(digit)
	return digit
}

func GetOSInfo(ip string) map[string]interface{} {
	var mu sync.Mutex

	osinfo := map[string]interface{}{
		"NetBIOS_domain_name":   "",
		"NetBIOS_computer_name": "",
		"DNS_domain_name":       "",
		"DNS_computer_name":     "",
	}

	conn, err := net.DialTimeout("tcp", ip+":135", TIME_OUT)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer conn.Close()

	digit := sendPacket(ip)

	buffer_v2 := []byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x78, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f}

	conn.SetWriteDeadline(time.Now().Add(TIME_OUT))
	_, err = conn.Write(buffer_v2)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	packet2 := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(TIME_OUT))
	n, err := conn.Read(packet2)
	packet2 = packet2[:n]
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	OS_Version_bytes := packet2[0xa0-54+10 : 0xa0-54+18]
	Major_Version := int(OS_Version_bytes[0])
	Minor_Version := int(OS_Version_bytes[1])
	Build_Number := int(binary.LittleEndian.Uint16(OS_Version_bytes[2:4]))
	OS_Version := fmt.Sprintf("Windows Version %d.%d Build %d %s", Major_Version, Minor_Version, Build_Number, digit)
	//OS_Version := fmt.Sprintf("Windows Version %d.%d Build %d", Major_Version, Minor_Version, Build_Number)

	Target_Info_Length_bytes := packet2[0xa0-54+2 : 0xa0-54+4]
	Target_Info_Length := int(binary.LittleEndian.Uint16(Target_Info_Length_bytes))
	Target_Info_bytes := packet2[len(packet2)-Target_Info_Length : len(packet2)-4]

	//输出多项结果，加锁
	mu.Lock()
	fmt.Println("[*] " + ip + " OS Info :")
	fmt.Println("\t[->] OS_Version :", OS_Version)
	for k := range osinfo {
		osinfo[k] = attributeName(Target_Info_bytes)
		fmt.Printf("\t[->] %s : %v\n", k, osinfo[k])
	}
	mu.Unlock()
	length = 0
	osinfo["OS_Version"] = OS_Version
	result := map[string]interface{}{ip: osinfo}
	return result
}

func GetNetworkInfo(ip string) interface{} {
	var mu sync.Mutex

	conn, err := net.DialTimeout("tcp", ip+":135", TIME_OUT)
	if err != nil {
		//fmt.Println("Error connecting:", err)
		//fmt.Println("Error connecting:", err)
		return -1
	}

	defer conn.Close()

	message := []byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00}
	message2 := []byte{0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00}

	_, err = conn.Write([]byte(message))
	if err != nil {
		//fmt.Println("Error sending message:", err)
		return -1
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		//fmt.Println("Error receiving message:", err)
		return -1
	}

	_, err = conn.Write([]byte(message2))
	if err != nil {
		//fmt.Println("Error sending message:", err)
		return -1
	}

	buffer2 := make([]byte, 4096)
	n, err2 := conn.Read(buffer2)
	if err2 != nil {
		//fmt.Println("Error receiving message:", err)
		return -1
	}

	result := buffer2[42:n]
	pattern := []byte{0x09, 0x00, 0xff, 0xff, 0x00, 0x00}
	pos := bytes.Index(result, pattern)
	result = result[:pos]
	//fmt.Println(result)

	hostname_list := bytes.Split(result[:], []byte{0x00, 0x00})
	ret := map[string][]string{ip: {}}
	//输出多项结果，加锁
	mu.Lock()

	fmt.Println("[*] " + ip + " Network Info :")

	for i := 0; i < len(hostname_list); i++ {
		j := bytes.Index(hostname_list[i], []byte{0x07, 0x00})
		if j != -1 {
			hostname_list[i] = append(hostname_list[i][:j], hostname_list[i][j+2:]...)
		}

		mark := true
		for mark == true {
			n := bytes.Index(hostname_list[i], []byte{0x00})
			if n != -1 && len(hostname_list[i]) > 1 {
				hostname_list[i] = append(hostname_list[i][:n], hostname_list[i][n+1:]...)
			} else {
				mark = false
			}
		}

		if len(hostname_list[i]) > 1 {
			fmt.Println("\t[->]" + string(hostname_list[i][:]))
			ret[ip] = append(ret[ip], string(hostname_list[i][:]))
		}

	}
	mu.Unlock()
	return ret
}

func IpFile(f string) ([]string, []error) {
	var ips []string
	var er []error

	file, err := os.Open(f)
	if err != nil {
		fmt.Println(err)
		return nil, er
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return nil, er
	}

	return ips, er
}

func OSInfotoTxt(result map[string]interface{}, Outputfile string) {
	// 将结果格式化为字符串
	var output strings.Builder
	for k, v := range result {
		output.WriteString(fmt.Sprintf("[*] %s\n", k))
		for k2, v2 := range v.(map[string]interface{}) {
			output.WriteString(fmt.Sprintf("\t[->] %s:%v\n", k2, v2))
		}
	}

	// 打开现有文件并附加结果
	f, err := os.OpenFile(Outputfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		//fmt.Println(err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(output.String())
	if err != nil {
		//fmt.Println(err)
		return
	}
}

func NetWorkInfotoTxt(result interface{}, Outputfile string) {
	// 将结果格式化为字符串

	var output strings.Builder
	for k, v := range result.(map[string][]string) {
		output.WriteString(fmt.Sprintf("[*] %s\n", k))
		for _, v2 := range v {
			output.WriteString(fmt.Sprintf("\t[->] %s\n", v2))
		}
	}

	// 打开现有文件并附加结果
	f, err := os.OpenFile(Outputfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		//fmt.Println(err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(output.String())

	if err != nil {
		//fmt.Println(err)
		return
	}
}

func main() {
	var ips []string
	var wg sync.WaitGroup

	var ip string
	var Threads int
	var Inputfile = ""
	var Outputfile = "result.txt"

	flag.StringVar(&ip, "i", "", "IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.0/24")
	flag.StringVar(&Inputfile, "l", "", "inputfile, for example: ip.txt，One ip in a row")
	flag.IntVar(&Threads, "t", 5, "Thread nums")
	flag.StringVar(&Outputfile, "o", "result.txt", "Outputfile")

	flag.Parse()

	if len(Inputfile) != 0 && len(ip) == 0 {
		ips, _ = IpFile(Inputfile)
	} else if len(ip) != 0 && len(Inputfile) == 0 {
		ips, _ = nmapIPRange.Handler(ip)
	} else {
		fmt.Println("need input ips")
		return
	}

	// 将IP地址列表分成多个小的子列表
	ipGroups := make([][]string, Threads)
	for i := range ipGroups {
		start := i * len(ips) / Threads
		end := (i + 1) * len(ips) / Threads
		ipGroups[i] = ips[start:end]
	}

	// 使用 WaitGroup 来等待所有线程执行完毕
	wg.Add(len(ips))

	// 创建一个互斥锁
	var mu sync.Mutex

	// 记录已经执行过的IP地址
	visited := make(map[string]bool)

	// 创建指定数量的 goroutine
	for i := 0; i < len(ips); i++ {
		go func(ip string) {
			// 加锁，保证并发安全
			mu.Lock()
			// 如果该IP地址已经被执行过，则直接返回
			if visited[ip] {
				mu.Unlock()
				wg.Done()
				return
			}
			// 标记该IP地址已经被执行过
			visited[ip] = true
			mu.Unlock()

			// 执行函数
			//fmt.Println(GetOSInfo(ip))
			result1 := GetOSInfo(ip)
			result2 := GetNetworkInfo(ip)

			for k, _ := range result1 {
				if k != "error" {
					OSInfotoTxt(result1, Outputfile)
				}
			}

			if result2 != -1 {
				NetWorkInfotoTxt(result2, Outputfile)
			}

			wg.Done()
		}(ips[i])
	}

	// 等待所有线程执行完毕
	wg.Wait()

	fmt.Println("All done!")
}
