package config

import (
	"fmt"
	"strconv"
	"strings"
)

var validSSHKeywords = map[string]struct{}{
	"host": {}, "match": {}, "hostname": {}, "user": {}, "port": {},
	"identityfile": {}, "identityagent": {}, "addkeystoagent": {},
	"forwardagent": {}, "serveraliveinterval": {}, "serveralivecountmax": {},
	"stricthostkeychecking": {}, "userknownhostsfile": {}, "loglevel": {},
	"compression": {}, "connecttimeout": {}, "proxyjump": {}, "proxycommand": {},
	"preferredauthentications": {}, "pubkeyauthentication": {},
	"passwordauthentication": {}, "batchmode": {}, "canonicalizehostname": {},
	"controlmaster": {}, "controlpath": {}, "controlpersist": {},
	"requesttty": {}, "remoteforward": {}, "localforward": {},
	"dynamicforward": {}, "exitonforwardfailure": {}, "sendenv": {},
	"setenv": {}, "xauthlocation": {}, "forwardx11": {}, "forwardx11trusted": {},
	"gssapiauthentication": {}, "gssapidelegatecredentials": {},
	"hostbasedauthentication": {}, "enableescapecommandline": {},
	"rekeylimit": {}, "tunnel": {}, "permitlocalcommand": {},
	"localcommand": {}, "visualhostkey": {}, "hashknownhosts": {},
	"checkhostip": {}, "addressfamily": {}, "bindaddress": {},
	"cipher": {}, "ciphers": {}, "macs": {}, "hostkeyalgorithms": {},
	"kexalgorithms": {}, "pubkeyacceptedalgorithms": {},
	"hostbasedacceptedalgorithms": {},
}

func isValidSSHKeyword(key string) bool {
	_, ok := validSSHKeywords[strings.ToLower(key)]
	return ok
}

// IsValidSSHKeyword reports whether key is a recognized ssh_config(5) keyword.
func IsValidSSHKeyword(key string) bool { return isValidSSHKeyword(key) }

var numericKeys = map[string]struct{}{
	"port": {}, "serveraliveinterval": {}, "serveralivecountmax": {}, "connecttimeout": {},
}

var boolKeys = map[string]struct{}{
	"forwardagent": {}, "addkeystoagent": {}, "forwardx11": {}, "forwardx11trusted": {},
	"compression": {}, "batchmode": {}, "canonicalizehostname": {},
	"exitonforwardfailure": {}, "permitlocalcommand": {}, "visualhostkey": {},
	"hashknownhosts": {}, "checkhostip": {}, "gssapiauthentication": {},
	"gssapidelegatecredentials": {}, "hostbasedauthentication": {},
	"pubkeyauthentication": {}, "passwordauthentication": {},
}

// ValidateParamValue returns a non-nil error if val is not acceptable for the given SSH keyword.
// Returns nil for unknown keys or keys with free-form values.
func ValidateParamValue(key, val string) error {
	if val == "" {
		return fmt.Errorf("value must not be empty")
	}
	low := strings.ToLower(key)
	if _, ok := numericKeys[low]; ok {
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("%s must be a number", key)
		}
		if low == "port" && (n < 1 || n > 65535) {
			return fmt.Errorf("port must be between 1 and 65535")
		}
		if n < 0 {
			return fmt.Errorf("%s must be non-negative", key)
		}
	}
	if _, ok := boolKeys[low]; ok {
		switch strings.ToLower(val) {
		case "yes", "no":
		default:
			return fmt.Errorf("%s must be yes or no", key)
		}
	}
	return nil
}
