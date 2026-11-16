# OCD Active Directory Mind Map — Parsed Taxonomy (v2025.03)

> Methodology, tooling, and target-capability basis for PLAN-003. Parsed from the
> Orange Cyberdefense public AD mind map. Structural skeleton + tool inventory here;
> full technique/command detail in the machine-readable sidecar
> `data/ocd-ad-mindmap-2025.03.taxonomy.json`.

## Provenance
- Source repo: `Orange-Cyberdefense/ocd-mindmaps`, pinned commit `6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e`
- Rendered map: `img/mindmap_ad_dark_classic_2025.03.excalidraw.svg` (sha256 `2816aa470c27773aee6aa69d7b71ebb90865aef27faa65a71764fdde445f5dbf`)
- Parsed source: `excalimap/mindmap/ad/*.md` (17 phase files + `conf.yml` tool registry)
- Parser: deterministic (`parse_mindmap.py`), no model generation of technique content
- Scale: 17 attack-phase categories · 128 subjects · 707 technique items · 450 commands · 20 CVE-tagged items · 151 tools referenced

## Engagement progression (matrix columns, left → right)

The map is a 7-column grid; each column is a stage of an AD engagement, stacked top-to-bottom by sub-phase.

- **Column 1:** No Credentials → Quick Compromise
- **Column 2:** Valid user (no password) → Man In The Middle (Listen and Relay) → Crack hash
- **Column 3:** Valid Credentials (cleartext creds, nt hash, kerberos ticket)
- **Column 4:** Low access (Privilege escalation) → Know vulnerabilities authenticated → ACLs/ACEs permissions
- **Column 5:** Kerberos Delegation → ADCS → SCCM
- **Column 6:** Admin access → Lateral Move
- **Column 7:** Domain admin → Trusts → Persistence

## Categories → subjects

### No Credentials
`no_creds` · 11 subjects · 17 tools

**Subjects:** Scan network · Find DC IP · Zone transfer · Anonymous & Guest access on SMB shares · Enumerate LDAP · Enumerate Users · Bruteforce users · Poisoning · Coerce · PXE · TimeRoasting

**Tools referenced:** Pcredz, bettercap, dig, enum4linux-ng.py, kerbrute, ldapsearch, mitm6, nmap, nmcli, nslookup, nxc, petitpotam.py, pxethief.py, responder, smbclient, tftp, timeroast.py

### Valid user (no password)
`valid_user` · 2 subjects · 13 tools

**Subjects:** Password Spray · ASREPRoast

**Tools referenced:** CVE-2022-33679.py, Get-ADDefaultDomainPasswordPolicy, Get-ADFineGainedPasswordPolicy, GetNPUsers.py, GetUserSPNs.py, MATCH, Rubeus.exe, hashcat, kerbrute, ldapsearch-ad.py, ldeep, nxc, sprayhound

### Valid Credentials (cleartext creds, nt hash, kerberos ticket)
`authenticated` · 9 subjects · 27 tools

**Subjects:** Classic Enumeration (users, shares, ACL, delegation, ...) · Enumerate ADCS · Enumerate SCCM · Scan Auto · Kerberoasting · Coerce · Intra ID Connect · Can Connect to a computer · Exploit

**Tools referenced:** AD-miner, GetADUsers.py, GetUserSPNs.py, Import-Module, MATCH, PingCastle.exe, Rubeus.exe, SOAPHound.exe, SharpSCCM.exe, adidnsdump, bloodhound-python, certify.exe, certipy, coercer.py, dnstool.py, ldapdomaindump.py, ldapsearch-ad.py, ldeep, manspider, ntlm_theft.py, nxc, petitpotam.py, printerbug.py, rusthound, rusthound-ce, sccmhunter.py, sharphound.exe

### Low access (Privilege escalation)
`low_access` · 8 subjects · 13 tools

**Subjects:** Bypass Applocker · UAC bypass · Auto Enum · Search files · Exploit · Webdav · Kerberos Relay · From Service account (SEImpersonate)

**Tools referenced:** .\PrivescCheck.ps1, Get-ChildItem, KrbRelayUp.exe, MsBuild.exe, dnstool.py, findstr, installutil.exe, msdt.exe, mshta.exe, petitpotam.py, vssadmin, winPEASany_ofs.exe, wsreset.exe

### Kerberos Delegation
`delegation` · 5 subjects · 8 tools

**Subjects:** Find delegation · Unconstrained delegation · Constrained delegation · Resource-Based Constrained Delegation · S4U2self abuse

**Tools referenced:** MATCH, Rubeus.exe, addcomputer.py, findDelegation.py, getST.py, getTGT.py, mimikatz, rbcd.py

### Admin access
`admin` · 6 subjects · 22 tools

**Subjects:** Extract credentials from LSASS.exe · Extract credentials from SAM · Extract credentials from LSA · Extract credentials from DPAPI · Impersonate · Misc

**Tools referenced:** DPAPImk2john.py, PPLdump64.exe, SharpDPAPI.exe, azuread_decrypt_msol_v2.ps1, donpapi, dpapidump.py, dploot.py, irs.exe, lsassy, masky, mimikatz, msf>, nxc, procdump.exe, psexec.exe, query, reg, reg.py, regsecrets.py, secretsdump.py, smbmap.py, tscon.exe

### Domain admin
`dom_admin` · 2 subjects · 6 tools

**Subjects:** Dump ntds.dit · Grab backup Keys

**Tools referenced:** certsync, donpapi, mimikatz, msf>, nxc, secretsdump.py

### Quick Compromise
`low_hanging` · 11 subjects · 12 tools

**Subjects:** ⚠️ Zerologon (unsafe) CVE-2020-1472 @CVE@ · Eternal Blue MS17-010 @CVE@ · Tomcat/Jboss Manager · Java RMI · Java Serialiszed port · Log4shell · Database · Exchange · Veeam · GLPI · Weak websites / services

**Tools referenced:** CVE-2023-27532, CVE-2024-29849.py, CVE-2024-29855.py, CVE-2024-40711.exe, VeeamHax.exe, cve-2020-1472-exploit.py, cve_2023_41320.py, msf>, nuclei, proxyshell_rce.py, ysoserial.jar, zerologon-scan

### Man In The Middle (Listen and Relay)
`mitm` · 3 subjects · 6 tools

**Subjects:** Listen · NTLM relay · Kerberos relay

**Tools referenced:** krbrelayx.py, msf>, ntlmrelayx.py, nxc, responder, smbclient.py

### Know vulnerabilities authenticated
`know_vuln_auth` · 7 subjects · 12 tools

**Subjects:** MS14-068 · GPP MS14-025 · PrivExchange (CVE-2019-0724, CVE-2019-0686) · noPac (CVE-2021-42287, CVE-2021-42278) · PrintNightmare (CVE-2021-1675, CVE-2021-34527) · Certifried (CVE-2022-26923) · ProxyNotShell (CVE-2022-41040, CVE-2022-41082)

**Tools referenced:** Get-GPPPassword.py, certipy, findSMB2UPTime.py, findstr, goldenPac.py, ms14-068.py, msf>, noPac.exe, nxc, poc_aug3.py, printnightmare.py, privexchange.py

### ADCS
`adcs` · 7 subjects · 7 tools

**Subjects:** Enumeration · Web Enrollment Is Up · Misconfigured Certificate Template · Misconfigured ACL · Vulnerable PKI Object access control · Misconfigured Certificate Authority · Abuse Certificate Mapping

**Tools referenced:** Rubeus.exe, certify.exe, certipy, certutil, gettgtpkinit.py, ldeep, ntlmrelayx.py

### Lateral Move
`lat_move` · 6 subjects · 28 tools

**Subjects:** Clear text Password · NT Hash · Kerberos · Socks (relay) · Certificate (pfx) · MSSQL

**Tools referenced:** Enter-PSSession, MATCH, Rubeus.exe, atexec.py, certipy, dcomexec.py, evil-winrm, getTGT.py, getnthash.py, gettgtpkinit.py, impacket, lookupsid.py, mimikatz, mssqlclient.py, nxc, passthecert.py, psexec.exe, psexec.py, psexecsvc.py, reg.py, secretsdump.py, smbclient-ng.py, smbclient.py, smbexec.py, tgssub.py, ticketConverter.py, wmiexec.py, xfreerdp

### Trusts
`trusts` · 5 subjects · 14 tools

**Subjects:** Enumeration · Child->Parent · Parent->Child · External Trust · Mssql links

**Tools referenced:** Get-DomainSID, Get-DomainTrust, Get-DomainTrustMapping, Get-SQLServerLinkCrawl, MATCH, ldeep, lookupsid.py, mimikatz, mssqlclient.py, nltest.exe, raiseChild.py, secretsdump.py, sharphound.exe, ticketer.py

### Crack hash
`crack_hash` · 10 subjects · 2 tools

**Subjects:** LM (299bd128c1101fd6) · NT (b4b9b02e6f09a9bd760...) · NTLMv1 (user::85D5BC...) · NTLMv2 (user::N46iSNek...) · Kerberos 5 TGS ($krb5tgs$23$...) · Kerberos 5 TGS AES128 ($krb5tgs$17...) · Kerberos ASREP ($krb5asrep$23...) · MSCache 2 (very slow) ($DCC2$10240...) · Timeroast hash ($sntp-ms$...) · pxe hash ($sccm$aes128$...)

**Tools referenced:** hashcat, john

### ACLs/ACEs permissions
`acl` · 10 subjects · 16 tools

**Subjects:** Dcsync · can change msDS-KeyCredentialLInk (Generic Write) + ADCS · On Group · On Computer · On User · On OU · ReadGMSAPassword · Get LAPS passwords · GPO · DNS Admin

**Tools referenced:** Get-DomainOU, Get-DomainObjectAcl, Get-LapsADPassword, MATCH, OUned.py, certipy, dnscmd.exe, gMSADumper.py, ldeep, mimikatz, msf>, nxc, pywhisker.py, sc, secretsdump.py, targetedKerberoast.py

### SCCM
`sccm` · 14 subjects · 17 tools

**Subjects:** recon · Creds-1 No credentials · Elevate-1:Relay on site systems Simple user · Elevate-2:Force client push Simple user · Elevate-3:Automatic client push Simple user · CRED-6 Loot creds · Takeover-1:relay to mssql db Simple user · Takeover-2:relay to mssql server Simple user · Creds-2:Policy Request Credentials Simple user · Creds-3Creds-4 Computer Admin user · Creds-5 SCCM admin · EXEC-1/2 SCCM admin · Cleanup · Post exploit

**Tools referenced:** SCCMHound.exe, SCCMSecrets.py, SharpSCCM.exe, cmloot.py, dnstool.py, dploot.py, ldeep, mssqlclient.py, ntlmrelayx.py, nxc, policysecretunobfuscate.py, query, sccm-http-looter, sccmhunter.py, sccmwtf.py, secretsdump.py, smbexec.py

### Persistence
`persistence` · 12 subjects · 4 tools

**Subjects:** ADD DA · Golden ticket · Silver Ticket · Directory Service Restore Mode (DSRM) · Skeleton Key · Custom SSP · Golden certificate · Diamond ticket · Saphire Ticket · DC shadow · ACL manipulation · ...

**Tools referenced:** PowerShell, certipy, mimikatz, ticketer.py

## Tool inventory by family
- **adminer** (1): AD-miner
- **bettercap** (1): bettercap
- **bloodhound** (2): MATCH, sharphound.exe
- **coercer** (1): coercer.py
- **donpapi** (1): donpapi
- **evilwinrm** (1): evil-winrm
- **github** (67): CVE-2022-33679.py, CVE-2023-27532, CVE-2024-29849.py, CVE-2024-29855.py, CVE-2024-40711.exe, DPAPImk2john.py, Get-DomainSID, Get-DomainTrust, Get-DomainTrustMapping, KrbRelayUp.exe, OUned.py, PPLdump64.exe, Pcredz, SCCMHound.exe, SCCMSecrets.py, SharpDPAPI.exe, VeeamHax.exe, adidnsdump, bloodhound-python, certify.exe, certipy, certsync, cmloot.py, cve-2020-1472-exploit.py, cve_2023_41320.py, dnstool.py, dpapidump.py, dploot.py, enum4linux-ng.py, findSMB2UPTime.py, gMSADumper.py, getnthash.py, gettgtpkinit.py, irs.exe, kerbrute, krbrelayx.py, ldapdomaindump.py, ldapsearch-ad.py, ldeep, lsassy, manspider, masky, mitm6, ms14-068.py, noPac.exe, ntlm_theft.py, passthecert.py, petitpotam.py, poc_aug3.py, policysecretunobfuscate.py, printerbug.py, printnightmare.py, privexchange.py, proxyshell_rce.py, psexecsvc.py, pxethief.py, pywhisker.py, regsecrets.py, responder, sccm-http-looter, sccmwtf.py, smbclient-ng.py, smbmap.py, sprayhound, targetedKerberoast.py, timeroast.py, zerologon-scan
- **hashcat** (1): hashcat
- **impacket** (26): Get-GPPPassword.py, GetADUsers.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, atexec.py, dcomexec.py, findDelegation.py, getST.py, getTGT.py, goldenPac.py, impacket, lookupsid.py, mssqlclient.py, ntlmrelayx.py, psexec.py, raiseChild.py, rbcd.py, reg.py, secretsdump.py, smbclient.py, smbexec.py, tgssub.py, ticketConverter.py, ticketer.py, wmiexec.py
- **john** (1): john
- **metasploit** (1): msf>
- **microsoft** (15): MsBuild.exe, certutil, dnscmd.exe, findstr, installutil.exe, msdt.exe, mshta.exe, procdump.exe, psexec.exe, query, reg, sc, tscon.exe, vssadmin, wsreset.exe
- **mimikatz** (1): mimikatz
- **nmap** (1): nmap
- **nuclei** (1): nuclei
- **nxc** (1): nxc
- **other** (7): dig, ldapsearch, nmcli, nslookup, smbclient, tftp, xfreerdp
- **pingcastle** (1): PingCastle.exe
- **powerupsql** (1): Get-SQLServerLinkCrawl
- **ps1** (12): .\PrivescCheck.ps1, Enter-PSSession, Get-ADDefaultDomainPasswordPolicy, Get-ADFineGainedPasswordPolicy, Get-ChildItem, Get-DomainOU, Get-DomainObjectAcl, Get-LapsADPassword, Import-Module, PowerShell, azuread_decrypt_msol_v2.ps1, nltest.exe
- **rubeus** (1): Rubeus.exe
- **rusthound** (1): rusthound
- **rusthoundce** (1): rusthound-ce
- **sccmhunter** (1): sccmhunter.py
- **sharpsccm** (1): SharpSCCM.exe
- **soaphound** (1): SOAPHound.exe
- **winpeas** (1): winPEASany_ofs.exe
- **ysoserial** (1): ysoserial.jar
