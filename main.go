package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/codingeasygo/util/proxy"
	"github.com/codingeasygo/util/proxy/http"
	"github.com/codingeasygo/util/proxy/socks"
	"github.com/codingeasygo/util/xhash"
	"github.com/codingeasygo/util/xio"
	"golang.org/x/crypto/ssh"
)

var username string
var id string
var password string
var listen string

func init() {
	flag.StringVar(&username, "l", "root", "the user to login")
	flag.StringVar(&id, "i", "~/.ssh/id_rsa", "id file")
	flag.StringVar(&password, "p", "", "the password to login")
	flag.StringVar(&listen, "n", "127.0.0.1:0", "the local listen addr")
	flag.Parse()
}

func main() {
	proxy.SetLogLevel(proxy.LogLevelDebug)
	socks.SetLogLevel(socks.LogLevelDebug)
	http.SetLogLevel(socks.LogLevelDebug)
	var err error
	args := flag.Args()
	if len(args) < 1 {
		fmt.Printf(`Usage: ssh-proxy <option> host <command>
       ssh-proxy -l 127.0.0.1:1080 remote
       ssh-proxy remote chrome
`)
		os.Exit(1)
		return
	}
	runnerPath := ""
	runnerPath, err = exec.LookPath("./chrome")
	if err != nil {
		runnerPath, err = exec.LookPath("chrome")
	}
	if err != nil {
		runnerPath, err = exec.LookPath("./google-chrome")
	}
	if err != nil {
		runnerPath, err = exec.LookPath("google-chrome")
	}
	if err != nil {
		runnerPath, err = exec.LookPath("./Google Chrome")
	}
	if err != nil {
		runnerPath, err = exec.LookPath("Google-Chrome")
	}
	if err != nil && runtime.GOOS == "windows" {
		runnerPath, err = exec.LookPath(`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`)
	}
	if err != nil && runtime.GOOS == "windows" {
		runnerPath, err = exec.LookPath(`C:\Program Files\Google\Chrome\Application\chrome.exe`)
	}
	if err != nil && runtime.GOOS == "darwin" {
		runnerPath, err = exec.LookPath(`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`)
	}
	if err != nil {
		fmt.Printf("Chrome search google chrome fail, add it to path\n")
		os.Exit(1)
		return
	}
	host := args[0]
	hostSHA := xhash.SHA1([]byte(host))
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".ssh", "cache", hostSHA)
	err = os.MkdirAll(dataDir, os.ModePerm)
	if err != nil {
		fmt.Printf("create datadir on %v fail with %v\n", dataDir, err)
		os.Exit(1)
		return
	}
	proxy.InfoLog("using google chrome on %v, datadir on %v", runnerPath, dataDir)

	//
	hostAddr := host
	if !strings.Contains(hostAddr, ":") {
		hostAddr = host + ":22"
	}
	fmt.Printf("start connect to %v\n", hostAddr)
	sshConf := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if len(sshConf.User) < 1 {
		user, err := user.Current()
		if err != nil {
			fmt.Printf("get current user fail with %v\n", err)
			os.Exit(1)
		}
		sshConf.User = user.Username
	}
	if len(password) > 0 {
		sshConf.Auth = append(sshConf.Auth, ssh.Password(password))
	}
	if len(id) > 0 {
		idFile := id
		if strings.HasPrefix(idFile, "~") {
			idFile = homeDir + strings.TrimPrefix(idFile, "~")
		}
		fmt.Printf("using id %v\n", idFile)
		signer, err := signerFromPem(idFile)
		if err != nil {
			fmt.Printf("read id %v fail with %v\n", id, err)
			os.Exit(1)
		}
		sshConf.Auth = append(sshConf.Auth, ssh.PublicKeys(signer))
	}
	sshConn, err := ssh.Dial("tcp", hostAddr, sshConf)
	if err != nil {
		fmt.Printf("dial to %v fail with %v\n", hostAddr, err)
		os.Exit(1)
		return
	}
	proxy.InfoLog("connect to %v success", hostAddr)
	defer sshConn.Close()
	server := proxy.NewServer(xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
		connURI, err := url.Parse(uri)
		if err != nil {
			return
		}
		conn, err := sshConn.Dial("tcp", connURI.Host)
		if err != nil {
			return
		}
		raw = xio.NewCopyPiper(conn, bufferSize)
		return
	}))
	proxy.InfoLog("start proxy on %v", listen)
	ln, err := server.Start(listen)
	if err != nil {
		fmt.Printf("listen on %v fail with %v\n", listen, err)
		os.Exit(1)
		return
	}
	proxy.InfoLog("listen proxy on %v", ln.Addr())
	if len(args) > 1 && args[1] == "chrome" {
		proxy.InfoLog("Chrome proxy all to %v", ln.Addr())
		runnerArgs := []string{}
		runnerArgs = append(runnerArgs, fmt.Sprintf("--proxy-server=socks5://%v", ln.Addr()))
		runnerArgs = append(runnerArgs, fmt.Sprintf("--proxy-bypass-list=\"%v\"", "<-loopback>"))
		runnerArgs = append(runnerArgs, fmt.Sprintf("--user-data-dir=%v", dataDir))
		cmd := exec.Command(runnerPath, runnerArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		fmt.Printf("Chrome done with %v\n", err)
	} else {
		server.Wait()
	}
}

func signerFromPem(filename string) (ssh.Signer, error) {

	// read file
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// read pem block
	err = errors.New("pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// generate signer instance from plain key
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing plain private key failed %v", err)
	}

	return signer, nil
}
