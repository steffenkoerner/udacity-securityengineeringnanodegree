rule unknown_threat
{
meta:
	author = "@steffenkoerner"
	version = "1.0"
strings:
     $domain = "mine.ppxxmr.com:7777"
condition:
     $domain
}
