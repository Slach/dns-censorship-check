package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/urfave/cli/v2"
	stdlog "log"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var domainRegexp = regexp.MustCompile("^(?:[_a-z\\d](?:[_a-z\\d-]{0,61}[a-z\\d])?\\.)+(?:[a-z](?:[a-z\\d-]{0,61}[a-z\\d])?)?$")

func main() {
	app := cli.NewApp()
	app.Name = "dns-censorship-check"
	app.Usage = "check DNS response from local system DNS, whois nameserver and multiple public dns and compare it to try detect DNS censorship"
	app.ArgsUsage = ""
	app.HideHelp = false
	app.Version = "2022.0.1"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Value:   "A",
			Usage:   "dns name which for checking",
		},
		&cli.StringFlag{
			Name:  "dns-servers-file",
			Value: "dns-servers.txt",
			Usage: "file name with list of publi dns",
		},
	}
	app.Action = run
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("check failed")
	}

}

func run(c *cli.Context) error {
	stdlog.SetOutput(log.Logger)
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	domain := c.Args().First()
	if !domainRegexp.MatchString(domain) {
		return fmt.Errorf("%s is not valid domain", domain)
	}
	_ = os.Setenv("JSON", "1")
	_ = os.Setenv("RRTYPE", c.String("type"))
	localDNSServers, err := getLocalDNSServers()
	if err != nil {
		return err
	}
	localDNSResponses, err := checkDNSResponse(domain, localDNSServers, "", false)
	if len(localDNSResponses) == 0 {
		return fmt.Errorf("can't resolve %s via local DNS servers %v", domain, localDNSServers)
	}
	publicDNSServers, err := getPublicDNSServers(c)
	if err != nil {
		return err
	}
	detect := 0
	emptyResponses := 0
	// protocols := []string{"tls://", "https://", "quic://"}
	protocols := []string{"tls://", "quic://"}
	for _, protocol := range protocols {
		globalDNSResponses, err := checkDNSResponse(domain, publicDNSServers, protocol, true)
		if err != nil {
			return err
		}
		if len(globalDNSResponses) == 0 {
			emptyResponses += 1
			continue
		}
		for _, globalDNSReponse := range globalDNSResponses {
			if !reflect.DeepEqual(localDNSResponses[0], globalDNSReponse) {
				localAnswer, _ := json.MarshalIndent(localDNSResponses[0], "", "  ")
				globalAnswer, _ := json.MarshalIndent(globalDNSReponse, "", "  ")
				log.Warn().Msgf("Censorship detected\n\n%v\n\nlocal answer was\n\n%v", globalAnswer, localAnswer)
				detect += 1
			}
		}
	}
	if emptyResponses == len(protocols) {
		return fmt.Errorf("can't get DNS response from %v servers via %v protocols", publicDNSServers, protocols)
	}
	if detect > 0 {
		return fmt.Errorf("censorship detected %d times", detect)
	}

	log.Info().Msgf("All DNS responses consistent. No censorship detected")
	return nil
}

func execCmdOut(cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	log.Info().Msgf("%s %s", cmd, strings.Join(args, " "))
	execCmd := exec.CommandContext(ctx, cmd, args...)
	out, err := execCmd.CombinedOutput()
	// @TODO WAT? why echo $? return non zero but golang can't detect it
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitStatus := exitErr.Error(); exitStatus != "0" {
			log.Warn().Msgf("Exit Status: %d", exitStatus)
		}
		cancel()
		return "", err
	}
	cancel()
	return string(out), err
}

/* @todo need find more proper way to get local DNS server setting */
func getLocalDNSServers() ([]string, error) {
	nameservers := make([]string, 0)
	replacer := strings.NewReplacer("{", "", "}", "")
	if runtime.GOOS == "windows" {
		ipconfig, err := execCmdOut("wmic.exe", "nicconfig", "list", "DNS", "/format:CSV")
		if err != nil {
			return nil, fmt.Errorf("wmic.exe return error: %v", err)
		}
		scanner := bufio.NewScanner(strings.NewReader(ipconfig))
		for scanner.Scan() {
			csv := strings.Split(scanner.Text(), ",")
			if len(csv) >= 7 && csv[6] != "" && csv[6] != "DNSServerSearchOrder" {
				servers := strings.Split(replacer.Replace(csv[6]), ";")
				for _, server := range servers {
					nameservers = append(nameservers, server)
				}
			}
		}
	} else {
		replacer := strings.NewReplacer("nameserver", "", " ", "", "\r", "", "\t", "", "\n", "")
		file, err := os.Open("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Error().Err(err).Str("file", "/etc/resolv.conf")
			}
		}()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			l := scanner.Text()
			if strings.Contains(l, "nameserver") {
				nameservers = append(nameservers, replacer.Replace(l))
			}
		}

		if err := scanner.Err(); err != nil {
			log.Error().Err(err)
			return nil, err
		}
	}
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("local DNS server not detected")
	}
	return nameservers, nil
}

func checkDNSResponse(domain string, servers []string, protocol string, returnAll bool) ([]string, error) {
	allReplies := make([]string, 0)
	reply := ""
	for _, server := range servers {
		// @TODO need properly deserialization and exec with pipes
		newReply, err := execCmdOut("bash", "-c", fmt.Sprintf("dnslookup %s %s%s | jq -c -r .Answer[].%s", domain, protocol, server, os.Getenv("RRTYPE")))
		if err != nil {
			log.Warn().Msgf("dnslookup return error: %v", err)
			continue
		}
		if reply == "" {
			reply = newReply
			continue
		}
		allReplies = append(allReplies, newReply)
		if newReply != reply {
			log.Warn().Msgf(
				"%s returns inconsistent DNS response\n\n%v\n\nfirst answer was\n\n%v", server, newReply, reply,
			)
		}
	}
	if returnAll {
		return allReplies, nil
	}
	return []string{reply}, nil
}

func getPublicDNSServers(c *cli.Context) ([]string, error) {
	file, err := os.Open(c.String("dns-servers-file"))
	nameservers := make([]string, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Err(err).Str("file", c.String("dns-servers-file"))
		}
	}()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		nameservers = append(nameservers, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err)
		return nil, err
	}
	return nameservers, nil
}
