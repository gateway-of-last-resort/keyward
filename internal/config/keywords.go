package config

import "strings"

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
