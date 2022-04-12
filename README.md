# CVE-2020-1472 aka Zerologon Exploit POC
![cve-2020-1742](https://user-images.githubusercontent.com/1679089/93808219-8a607c00-fc00-11ea-9a19-5128a5a533e6.gif)

## What is it?
NetLogon (MS-NRPC), can establish inter-domain control vulnerable security channel.
It's possible to zero out the password for the machine account on domain controllers.

## Notes:
- DC will be semi broken while password is zero'ed out, however this program changes the password back when its finished
- Could cause DNS issues with DC (fixed with reboot) 
- Kerberos Tickets have a 10 hour lifetime before they expire
- Requires the latest impacket from [GitHub](https://github.com/SecureAuthCorp/impacket) with added netlogon structures.
- Do note that by default this changes the password of the domain controller system account then changes it back. Yes this allows you to DCSync, but it also breaks communication with other domain controllers in the short timeframe, so be careful with this!

## Research it:
- https://www.secura.com/pathtoimg.php?id=2055
- https://twitter.com/_dirkjan/status/1306280553281449985
- For more info and original research view [blog](https://www.secura.com/blog/zero-logon) or review the
[whitepaper](https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM/)

## Required Dependencies
- Requires the latest impacket from [GitHub](https://github.com/SecureAuthCorp/impacket) with added netlogon structures.

## Check if vulnerable:
- Default behavior of script is to check if vulnerable and not change anything!

## Usage zerologon.py
* Read the blog/whitepaper above so you know what you're doing
* This script will check domain controllers for CVE-2020-1472.
* If -exploit option provided it will:
  * Zero out the domain controllers system password
  * Will call secretsdump's DRSUAPI with the zeropassword to get ntds hashes
  * Will parse dumped data to get domain admin account with rid :500: and call secretsdump again to get lsa secrets 
  * Will parse second dump for plain_password_hex value 
  * will call restore script with hex value to restore the DC's system password to its original value
  
 ```bash
python zerologon.py 

usage: zerologon.py [-h] [-exploit] dc_name dc_ip

Tests whether a domain controller is vulnerable to the Zerologon attack. Resets the DC account password to an empty string
when vulnerable.

positional arguments:
  dc_name     The (NetBIOS) computer name of the domain controller.
  dc_ip       IP Address of the domain controller.

optional arguments:
  -h, --help  show this help message and exit
  -exploit    Zero out the computer's hash
```
		
## Detect it:
* Event 4661 with privilege request for SetPassword (without knowledge of old password) (screenshot attached)
* Event 4723 for an attempt made to change an account's password
* Event 4738 for a user account being changed for the Password Last Set value
		
## Patch it:
- [CVE-2020-1472 | Netlogon Elevation of Privilege Vulnerability](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472)
- [How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc)
- [MITRE CVE-2020-1472](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472)

# Affected systems:
- Windows Server 2008 R2 for x64-based Systems Service Pack 1
- Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
- Windows Server 2012
- Windows Server 2012 (Server Core installation)
- Windows Server 2012 R2
- Windows Server 2012 R2 (Server Core installation)
- Windows Server 2016
- Windows Server 2016 (Server Core installation)
- Windows Server 2019
- Windows Server 2019 (Server Core installation)
- Windows Server, version 1903 (Server Core installation)
- Windows Server, version 1909 (Server Core installation)
- Windows Server, version 2004 (Server Core installation)
