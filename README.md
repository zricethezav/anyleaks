# anyleaks

Ever wanted to run gitleaks on something that isn't a git repo? Well now you can with anyleaks. Compatible with gitleaks configs.
### Examples:
```
./stream_data_from_socket.sh | anyleaks --pretty
```
or 
```
anyleaks --pretty -f file_to_audit.txt
```

### Help
```
Usage:
  anyleaks [OPTIONS]

Application Options:
      --config=  Config path
      --threads= Maximum number of threads gitleaks spawns
      --redact   Redact secrets from log messages and leaks
      --pretty   Pretty print json if leaks are present
  -f, --file=    File to audit

Help Options:
  -h, --help     Show this help message
```
