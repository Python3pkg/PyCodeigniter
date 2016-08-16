package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	random "math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/astaxie/beego/httplib"
	"github.com/howeyc/gopass"
	"github.com/sjqzhang/daemon"
)

var stdlog, errlog *log.Logger

type EtcdConf struct {
	Prefix string
	Server []string
}

type Config struct {
	EnterURL      string
	DefaultModule string
	DefaultAction string
	ScriptPath    string
	Salt          string
	Args          []string
	EtcdConf      *EtcdConf
	Commands      chan map[string]interface{}
	_Args         string
	_ArgsSep      string
}

func NewConfig() *Config {

	server := os.Getenv("CLI_SERVER")
	EnterURL := "http://127.0.0.1:8005"
	DefaultModule := "cli"

	if server != "" && strings.HasPrefix(server, "http") {
		if info, ok := url.Parse(server); ok == nil {
			if len(info.Path) > 0 {
				DefaultModule = info.Path[1:]
			}
			EnterURL = info.Scheme + "://" + info.Host
		}

	}

	conf := &Config{
		//		EnterURL: "http://172.17.140.133:8005",
		EnterURL:      EnterURL,
		DefaultModule: DefaultModule,
		Salt:          "",
		EtcdConf: &EtcdConf{
			Prefix: "",
			Server: []string{},
		},
		ScriptPath:    "/tmp/script/",
		DefaultAction: "help",
		Commands:      make(chan map[string]interface{}, 1000),
		Args:          os.Args,
		_ArgsSep:      "$$$$",
		_Args:         strings.Join(os.Args, "$$$$"),
	}
	os.MkdirAll(conf.ScriptPath, 0777)
	return conf
}

type Common struct {
}

func (this *Common) GetArgsMap() map[string]string {

	return this.ParseArgs(strings.Join(os.Args, "$$$$"), "$$$$")

}

func (this *Common) Home() (string, error) {
	user, err := user.Current()
	if nil == err {
		return user.HomeDir, nil
	}

	if "windows" == runtime.GOOS {
		return this.homeWindows()
	}

	return this.homeUnix()
}

func (this *Common) homeUnix() (string, error) {
	// First prefer the HOME environmental variable
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}

	// If that fails, try the shell
	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "eval echo ~$USER")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}

	result := strings.TrimSpace(stdout.String())
	if result == "" {
		return "", errors.New("blank output when reading home directory")
	}

	return result, nil
}

func (this *Common) homeWindows() (string, error) {
	drive := os.Getenv("HOMEDRIVE")
	path := os.Getenv("HOMEPATH")
	home := drive + path
	if drive == "" || path == "" {
		home = os.Getenv("USERPROFILE")
	}
	if home == "" {
		return "", errors.New("HOMEDRIVE, HOMEPATH, and USERPROFILE are blank")
	}

	return home, nil
}

func (this *Common) GetAllIps() []string {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		ip := addr.String()
		pos := strings.Index(ip, "/")
		if match, _ := regexp.MatchString("(\\d+\\.){3}\\d+", ip); match {
			if pos != -1 {
				ips = append(ips, ip[0:pos])
			}
		}
	}
	return ips
}

func (this *Common) GetLocalIP() string {

	ips := this.GetAllIps()
	for _, v := range ips {
		if strings.HasPrefix(v, "10.") || strings.HasPrefix(v, "172.") || strings.HasPrefix(v, "172.") {
			return v
		}
	}
	return "127.0.0.1"

}

func (this *Common) JsonEncode(v interface{}) string {

	if v == nil {
		return ""
	}
	jbyte, err := json.Marshal(v)
	if err == nil {
		return string(jbyte)
	} else {
		return ""
	}

}

func (this *Common) JsonDecode(jsonstr string) interface{} {

	var v interface{}
	err := json.Unmarshal([]byte(jsonstr), &v)
	if err != nil {
		return nil

	} else {
		return v
	}

}

func (this *Common) ParseArgs(args string, sep string) map[string]string {

	ret := make(map[string]string)

	var argv []string

	argv = strings.Split(args, sep)

	for i, v := range argv {
		if strings.HasPrefix(v, "-") && len(v) == 2 {
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				ret[v[1:]] = argv[i+1]
			}
		}

	}
	for i, v := range argv {
		if strings.HasPrefix(v, "-") && len(v) == 2 {
			if i+1 < len(argv) && strings.HasPrefix(argv[i+1], "-") {
				ret[v[1:]] = "1"
			} else if i+1 == len(argv) {
				ret[v[1:]] = "1"
			}
		}

	}

	for i, v := range argv {
		if strings.HasPrefix(v, "--") && len(v) > 3 {
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "--") {
				ret[v[2:]] = argv[i+1]
			}
		}

	}
	for i, v := range argv {
		if strings.HasPrefix(v, "--") && len(v) > 3 {
			if i+1 < len(argv) && strings.HasPrefix(argv[i+1], "--") {
				ret[v[2:]] = "1"
			} else if i+1 == len(argv) {
				ret[v[2:]] = "1"
			}
		}

	}

	return ret

}

func (this *Common) GetModule(conf *Config) string {

	if len(os.Args) > 2 {
		if !strings.HasPrefix(os.Args[1], "-") && !strings.HasPrefix(os.Args[2], "-") {
			return os.Args[1]
		} else {
			return conf.DefaultModule
		}
	} else if len(os.Args) == 2 {
		return conf.DefaultModule
	} else {
		return conf.DefaultModule
	}

}

func (this *Common) MD5(str string) string {

	md := md5.New()
	md.Write([]byte(str))
	return fmt.Sprintf("%x", md.Sum(nil))
}

func (this *Common) GetHostName() string {

	return ""
}

func (this *Common) IsExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func (this *Common) ReadFile(path string) string {
	if this.IsExist(path) {
		fi, err := os.Open(path)
		if err != nil {
			return ""
		}
		defer fi.Close()
		fd, err := ioutil.ReadAll(fi)
		return string(fd)
	} else {
		return ""
	}
}

func (this *Common) WriteFile(path string, content string) bool {
	var f *os.File
	var err error
	if this.IsExist(path) {
		f, err = os.OpenFile(path, os.O_RDWR, 0666)

	} else {
		f, err = os.Create(path)

	}
	if err == nil {
		defer f.Close()
		if _, err = io.WriteString(f, content); err == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}

}

func (this *Common) GetProductUUID() string {

	filename := "/sys/devices/virtual/dmi/id/product_uuid"
	uuid := this.ReadFile(filename)
	if uuid == "" {
		filename = "/etc/uuid"
		if this.IsExist(filename) {
			uuid = this.ReadFile(filename)
		} else {
			os.Mkdir(filename, 0666)
		}
		if uuid == "" {
			uuid := this.GetUUID()
			this.WriteFile(filename, uuid)

		}

	}

	return strings.Trim(uuid, "\n")

}

func (this *Common) Download(url string, data map[string]string) []byte {

	req := httplib.Post(url)
	for k, v := range data {
		req.Param(k, v)
	}
	str, err := req.Bytes()

	if err != nil {

		return nil

	} else {
		return str
	}
}

func (this *Common) Exec(cmd []string, timeout int) (string, int) {

	var out bytes.Buffer

	sig := syscall.SIGKILL

	duration := time.Duration(timeout) * time.Second

	command := exec.Command(cmd[0], cmd[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = &out
	command.Stderr = &out

	err := command.Start()
	if err != nil {
		//		die2(fmt.Sprintf("[timeout] Can't start the process: %v", err), 127)
	}

	timer := time.AfterFunc(duration, func() {
		//		if err := command.Process.Signal(sig); err != nil {
		//			fmt.Fprintf(os.Stderr, "[timeout] Can't kill the process: %v\n", err)
		//			command.Process.Release()
		//			print(command.Process.Pid)
		//		}
		print("killed processid", command.Process.Pid)
		command.Process.Kill()

	})

	err = command.Wait()

	killed := !timer.Stop()

	status := 0
	if killed {
		if sig == syscall.SIGKILL {
			status = 132
		} else {
			status = 124
		}
	} else if err != nil {
		if command.ProcessState == nil {
		}
		status = command.ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
	} else {
		status = 0
	}

	return out.String(), status

}

func (this *Common) GetUUID() string {

	b := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	id := this.MD5(base64.URLEncoding.EncodeToString(b))
	return fmt.Sprintf("%s-%s-%s-%s-%s", id[0:8], id[8:12], id[12:16], id[16:20], id[20:])

}

func (this *Common) GetAction(conf *Config) string {

	if len(os.Args) >= 3 {
		if !strings.HasPrefix(os.Args[2], "-") {
			return os.Args[2]
		} else if !strings.HasPrefix(os.Args[1], "-") {
			return os.Args[1]
		} else {
			return conf.DefaultAction
		}
	} else if len(os.Args) == 2 && !strings.HasPrefix(os.Args[1], "-") {
		return os.Args[1]
	} else {
		return conf.DefaultAction
	}

}

func (this *Common) Request(url string, data map[string]string) string {
	body := "{}"

	for _, k := range []string{"i", "s"} {
		if _, ok := data[k]; !ok {
			switch k {
			case "i":
				data[k] = this.GetLocalIP()
			case "s":
				data[k], _ = os.Hostname()
			}
		}

	}

	if pdata, err := json.Marshal(data); err == nil {
		body = string(pdata)
	}
	req := httplib.Post(url)
	if dir, ok := this.Home(); ok == nil {
		filename := dir + "/" + ".cli"
		uuid := this.ReadFile(filename)
		if uuid != "" {
			req.Header("auth-uuid", uuid)
		}
	}

	req.Param("param", body)
	req.SetTimeout(time.Second*10, time.Second*60)
	str, err := req.String()
	if err != nil {
		print(err)
	}
	return str
}

type Cli struct {
	util    *Common
	conf    *Config
	_daemon *Daemon
}

func (this *Cli) Default(module string, action string) {
	data := this.util.GetArgsMap()
	resp := this._Request(this.conf.EnterURL+"/"+module+"/"+action, data)

	var v interface{}
	if ok := json.Unmarshal([]byte(resp), &v); ok == nil {
		if buf, ok := json.MarshalIndent(v, "", "  "); ok == nil {
			resp = string(buf)
		}
	}

	fmt.Println(resp)
}

func (this *Cli) _Default(module string, action string, data map[string]string) {

	resp := this._Request(this.conf.EnterURL+"/"+module+"/"+action, data)
	fmt.Println(resp)
}

func (this *Cli) _Request(url string, data map[string]string) string {
	resp := this.util.Request(url, data)
	return resp
}

func (this *Cli) Request(url string, data map[string]string) {
	resp := this.util.Request(url, data)
	fmt.Println(resp)
}

func (this *Cli) Heartbeat() {

	for {
		data := map[string]string{
			"ips":  strings.Join(this.util.GetAllIps(), ","),
			"uuid": this.util.GetProductUUID(),
		}

		url := this.conf.EnterURL + "/" + this.conf.DefaultModule + "/" + "heartbeat"

		heartbeats := this._Request(url, data)
		var js map[string]interface{}
		ok := json.Unmarshal([]byte(heartbeats), &js)
		if ok == nil {
			this.conf.Salt = js["salt"].(string)
			server := this.util.JsonEncode(js["etcd"])
			var etcd EtcdConf
			json.Unmarshal([]byte(server), &etcd)
			this.conf.EtcdConf = &etcd

			print(this.conf.EtcdConf.Server)

		}
		r := random.New(random.NewSource(time.Now().UnixNano()))
		interval := time.Duration(60 + r.Intn(60))

		print("interval", interval)

		time.Sleep(interval * time.Second)
	}

}

func (this *Cli) Heartbeat2Etcd() {

	for {

		server := ""
		prefix := ""
		if len(this.conf.EtcdConf.Server) > 0 && this.conf.EtcdConf.Prefix != "" {
			server = this.conf.EtcdConf.Server[0]
			prefix = this.conf.EtcdConf.Prefix
			uuid := this.util.GetProductUUID()
			ips := this.util.GetAllIps()
			heartbeat_url := "http://" + server + "/v2/keys" + prefix + "/heartbeat/" + uuid
			req := httplib.Put(heartbeat_url)
			req.SetTimeout(time.Second*30, time.Second*30)
			req.Param("ttl", "300")
			req.Param("value", strings.Join(ips, ","))
			req.String()

		} else {
			print("Error Etcd Config")
		}

		r := random.New(random.NewSource(time.Now().UnixNano()))
		interval := time.Duration(60 + r.Intn(60))
		time.Sleep(interval * time.Second)

	}

}

func (this *Cli) DealCommands() {

	for {

		select {
		case item := <-this.conf.Commands:
			var cmd map[string]string
			timeout := 60
			json.Unmarshal([]byte(item["value"].(string)), &cmd)
			md5 := this.util.MD5(cmd["cmd"] + this.conf.Salt)
			print("item", item)
			if md5 == cmd["md5"] {
				url := "http://" + this.conf.EtcdConf.Server[0] + "/v2/keys" + item["key"].(string)
				print(url)
				req := httplib.Delete(url)
				print(req.String())

				if to, ok := strconv.Atoi(cmd["timeout"]); ok == nil {
					timeout = to

				}

				os := strings.ToLower(runtime.GOOS)
				result := ""
				switch os {

				case "linux":
					cmds := []string{
						"/bin/bash",
						"-c",
						cmd["cmd"],
					}

					CallBack := func() {

						result, _ = this.util.Exec(cmds, timeout)

						index := item["createdIndex"]

						data := map[string]string{
							"result": result,
							"ip":     "",
							"index":  fmt.Sprintf("%0.0f", index),
						}

						this._Request(this.conf.EnterURL+"/"+this.conf.DefaultModule+"/feedback_result", data)

					}

					go CallBack()

				case "windows":
					cmds := []string{
						cmd["cmd"],
						"",
						"",
					}
					CallBack := func() {
						result, _ = this.util.Exec(cmds, timeout)

						index := item["createdIndex"]

						data := map[string]string{
							"result": result,
							"ip":     "",
							"index":  fmt.Sprintf("%0.0f", index),
						}

						this._Request(this.conf.EnterURL+"/"+this.conf.DefaultModule+"/feedback_result", data)

					}

					go CallBack()

				}

			} else {
				print("sign error", item["key"])
				url := "http://" + this.conf.EtcdConf.Server[0] + "/v2/keys" + item["key"].(string)
				print(url)
				req := httplib.Delete(url)

				req.String()

			}

		}
	}

}

func (this *Cli) WatchEtcd() {

	GetNodeURL := func() string {
		server := ""
		prefix := ""
		if len(this.conf.EtcdConf.Server) > 0 && this.conf.EtcdConf.Prefix != "" {
			server = this.conf.EtcdConf.Server[0]
			prefix = this.conf.EtcdConf.Prefix
			uuid := this.util.GetProductUUID()
			url := "http://" + server + "/v2/keys" + prefix + "/servers/" + uuid
			return url
		}
		return ""

	}

	DealWithData := func() {

		url := GetNodeURL()
		if url != "" {
			url = url + "?recursive=true"
			req := httplib.Get(url)
			result, ok := req.String()
			if ok == nil {

				print(result)
				var v map[string]interface{}
				var items []map[string]interface{}

				json.Unmarshal([]byte(result), &v)
				json.Unmarshal([]byte(this.util.JsonEncode(v["node"])), &v)
				json.Unmarshal([]byte(this.util.JsonEncode(v["nodes"])), &items)

				for _, k := range items {
					this.conf.Commands <- k

				}

			}
		}

	}

	for {

		url := GetNodeURL()
		if url != "" {
			url = url + "?wait=true&recursive=true"
			req := httplib.Get(url)
			_, ok := req.String()
			if ok == nil {

				DealWithData()

			}
		}

	}

}

func (this *Cli) Daemon(module string, action string) {

	if msg, _ := this._daemon.Manage(this); msg != "" {
		print(msg)

	}

}

func (this *Cli) Login(module string, action string) {

	user, password := this._UserInfo()

	data := map[string]string{
		"u": user,
		"p": password,
	}

	res := this._Request(this.conf.EnterURL+"/"+this.conf.DefaultModule+"/login", data)

	if dir, ok := this.util.Home(); ok == nil {
		filename := dir + "/" + ".cli"
		if this.util.WriteFile(filename, res) {
			if len(res) == 36 {
				fmt.Println("success")
			} else {
				fmt.Println(res)
			}
		} else {
			fmt.Println(res)
		}
	}

	//	print(res)
}

func (this *Cli) _UserInfo() (string, string) {
	argv := this.util.GetArgsMap()
	var password string
	var user string
	if _user, ok := argv["u"]; ok {
		user = _user
	} else {
		fmt.Println("please input username:")
		fmt.Scanln(&user)
	}
	if _password, ok := argv["p"]; ok {
		password = _password
	} else {
		fmt.Println("please input password:")
		_password, er := gopass.GetPasswd()
		if er != nil {
		} else {
			password = string(_password)
		}
	}
	return user, password
}

func (this *Cli) Logout(module string, action string) {

	print(module)
	print(action)

}

func (this *Cli) Register(module string, action string) {

	user, password := this._UserInfo()
	data := map[string]string{
		"u": user,
		"p": password,
	}
	this._Default(module, action, data)

}

func (this *Cli) Shell(module string, action string) {

	argv := this.util.GetArgsMap()
	file := ""
	dir := ""
	ok := true

	if file, ok = argv["f"]; !ok {
		fmt.Println("-f(filename) is required")
		return
	}

	if dir, ok = argv["d"]; !ok {
		dir = "shell"
	}

	path := this.conf.ScriptPath + dir
	if !this.util.IsExist(path) {
		os.MkdirAll(path, 0777)
	}
	req := httplib.Post(this.conf.EnterURL + "/" + this.conf.DefaultModule + "/shell")
	req.Param("dir", dir)
	req.Param("file", file)
	filepath := path + "/" + file
	filepath = strings.Replace(filepath, "///", "/", -1)
	filepath = strings.Replace(filepath, "//", "/", -1)
	req.ToFile(filepath)
	os.Chmod(filepath, 0777)
	result := ""
	cmds := []string{
		filepath,
	}
	cmds = append(cmds, os.Args[4:]...)
	result, _ = this.util.Exec(cmds, 3600)
	fmt.Println(result)

}

func (this *Cli) Download(module string, action string) {
	argv := this.util.GetArgsMap()
	if filename, ok := argv["f"]; ok {
		var dir string
		var des string
		if d, ok := argv["d"]; ok {
			dir = d
		} else {
			dir = "/"
		}
		if _d, ok := argv["o"]; ok {
			des = _d
		} else {
			des = filename
		}
		req := httplib.Post(this.conf.EnterURL + "/" + this.conf.DefaultModule + "/download")
		req.Param("file", argv["f"])
		req.Param("dir", dir)
		req.ToFile(des)

	} else {
		fmt.Println("-f(filename) is required")
	}

}

func (this *Cli) Upload(module string, action string) {
	argv := this.util.GetArgsMap()
	if filename, ok := argv["f"]; ok {
		var dir string
		if d, ok := argv["d"]; ok {
			dir = d
		}
		req := httplib.Post(this.conf.EnterURL + "/" + this.conf.DefaultModule + "/upload")
		req.PostFile("file", filename)

		if pos := strings.LastIndex(filename, "/"); pos != -1 && !strings.HasSuffix(filename, "/") {
			req.Param("filename", filename[pos+1:])
		} else {
			req.Param("filename", filename)
		}
		req.Param("dir", dir)
		str, err := req.String()
		if err != nil {
			print(err)
		}
		fmt.Println(str)

	} else {
		fmt.Println("-f(filename) is required")
	}

}

func (this *Cli) Adddoc(module string, action string) {

	argv := this.util.GetArgsMap()
	if file, ok := argv["f"]; ok {
		argv["d"] = this.util.ReadFile(file)
	}
	res := this._Request(this.conf.EnterURL+"/"+this.conf.DefaultModule+"/adddoc", argv)
	fmt.Println(res)

}

func (this *Cli) Rexec(module string, action string) {
	user, password := this._UserInfo()
	data := map[string]string{
		"u": user,
		"p": password,
	}
	res := this._Request(this.conf.EnterURL+"/"+this.conf.DefaultModule+"/rexec", data)
	fmt.Println(res)

}

func (this *Cli) Downlaod(module string, action string) {

	argv := this.util.GetArgsMap()

	if filename, ok := argv["f"]; ok {
		var dir string
		if d, ok := argv["d"]; ok {
			dir = d
		}
		req := httplib.Post(this.conf.EnterURL + "/" + this.conf.DefaultModule + "/" + action)
		req.Param("file", filename)
		req.Param("dir", dir)
		str, err := req.String()
		if err != nil {
			print(err)
		}
		fmt.Println(str)

	} else {
		fmt.Println("-f(filename) is required")
	}

}

func print(args ...interface{}) {

	fmt.Println(args)

}

type Daemon struct {
	daemon.Daemon
}

func (this *Daemon) Manage(cli *Cli) (string, error) {

	usage := "Usage: cli daemon -s [install | remove | start | stop | status]"

	// if received any kind of command, do it
	var command string
	if len(os.Args) > 3 {
		command = os.Args[3]
		print(command)
		switch command {
		case "install":
			return this.Install(" daemon -s daemon ")
		case "remove":
			return this.Remove()
		case "start":
			return this.Start()
		case "daemon":

			print("daemon")

		case "stop":
			return this.Stop()
		case "status":
			return this.Status()
		default:
			return usage, nil
		}
	} else {
		return usage, nil
	}

	go cli.Heartbeat()
	time.Sleep(time.Second * 3)
	go cli.Heartbeat2Etcd()
	go cli.WatchEtcd()
	go cli.DealCommands()

	for {

		time.Sleep(time.Second * 5)

	}

	return usage, nil
}

func init() {

	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Llongfile)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

}

func test() {

	var v float64
	v = 69739179

	a := fmt.Sprintf("%0.0f", v)

	//	fmt.Println(strconv.Atoi(a))

	fmt.Println(a)

}

func main() {

	conf := NewConfig()
	util := &Common{}
	cli := &Cli{}
	cli.util = util
	cli.conf = conf
	obj := reflect.ValueOf(cli)
	_daemon, _ := daemon.New("cli", "cli daemon")
	daemon := &Daemon{_daemon}
	cli._daemon = daemon

	module := util.GetModule(conf)
	action := util.GetAction(conf)

	for i := 0; i < obj.NumMethod(); i++ {
		if obj.MethodByName(strings.Title(action)).IsValid() {
			obj.MethodByName(strings.Title(action)).Call([]reflect.Value{reflect.ValueOf(module), reflect.ValueOf(action)})
			break
		} else if i == obj.NumMethod()-1 {
			obj.MethodByName("Default").Call([]reflect.Value{reflect.ValueOf(module), reflect.ValueOf(action)})
		}
	}

}
