rule unknown_threat
{
meta:
	author = "@steffenkoerner"
	version = "1.0"
strings:
     $domain = "darkl0rd.com:7758"
condition:
     $domain
}
