package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

type Leak struct {
	LineNumber int    `json:"lineNumber"`
	Line       string `json:"line"`
	Offender   string `json:"offender"`
	Rule       string `json:"rule"`
	Tags       string `json:"tags"`
}

type Options struct {
	Config      string `long:"config" description:"config path"`
	Threads     int    `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	Redact      bool   `long:"redact" description:"redact secrets from log messages and leaks"`
	PrettyPrint bool   `long:"pretty" description:"Pretty print json if leaks are present"`
	File        string `long:"file" short:"f" description:"file to audit"`
}

var (
	leaks    []Leak
	leakChan chan Leak
)

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	cfg, err := NewConfig(opts.Config)
	if err != nil {
		log.Fatal(err)
	}

	stat, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}

	var r io.ReadCloser
	if (stat.Mode() & os.ModeNamedPipe) != 0 {
		r = os.Stdin
	} else {
		r, err = os.Open(opts.File)
		if err != nil {
			log.Fatal(err)
		}
	}

	leakChan = make(chan Leak)
	go receiveLeaks(opts)

	audit(r, cfg, opts)
}

func audit(r io.ReadCloser, cfg Config, opts Options) {
	defer r.Close()

	semaphore := make(chan bool, howManyThreads(opts.Threads))
	wg := sync.WaitGroup{}
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		txt := scanner.Text()

		wg.Add(1)
		semaphore <- true

		go func(txt string) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			for _, rule := range cfg.Rules {
				matches := rule.Regex.FindAllString(txt, -1)
				if len(matches) != 0 {
					for _, match := range matches {
						leakChan <- Leak{
							LineNumber: lineNum,
							Line:       txt,
							Offender:   match,
							Rule:       rule.Description,
							Tags:       strings.Join(rule.Tags, " "),
						}
					}
				}
			}
		}(txt)
		lineNum += 1
	}
}

// of goroutines that will spawn during anyleaks execution
func howManyThreads(threads int) int {
	maxThreads := runtime.GOMAXPROCS(0)
	if threads == 0 {
		return 1
	} else if threads > maxThreads {
		log.Warnf("%d threads set too high, setting to system max, %d", threads, maxThreads)
		return maxThreads
	}
	return threads
}

func receiveLeaks(opts Options) {
	for leak := range leakChan {
		var b []byte
		if opts.PrettyPrint {
			b, _ = json.MarshalIndent(leak, "", "	")
		} else {
			b, _ = json.Marshal(leak)
		}
		fmt.Println(string(b))
	}
}

