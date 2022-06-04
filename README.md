# dns-censorship-check
Requirements
```bash
go get github.com/ameshkov/dnslookup
apt-get install jq bash
```


```bash
NAME:
   dns-censorship-check - check DNS response from local system DNS, whois nameserver and multiple public dns and compare it to try detect DNS censorship

USAGE:
   dns-censorship-check [global options] command [command options] [arguments...]

VERSION:
   2022.0.1

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --dns-servers-file value  file name with list of publi dns (default: "dns-servers.txt")
   --help, -h                show help (default: false)
   --type value, -t value    dns name which for checking (default: "A")
   --version, -v             print the version (default: false)
```