## TURN 4 — codex — 26OCT2026

### Q8 — Coverage matrix

The current Aranum tree contains 76 dispatcher paths: 74 scripts plus `enum-https.sh → enum-http.sh` and `enum-xmpp.sh → enum-jabber.sh`. *(measured)*

Status meanings: `covered` means PurpleSploit’s dedicated modules collectively equal or exceed the dispatcher; `overlap` means both sides independently implement substantial service-specific enumeration; `partial` means PurpleSploit provides only a subset or generic Nmap/web building block; `missing` means no materially equivalent PurpleSploit enumeration module exists. Generic `-sCV` discovery alone does not count as service enumeration. *(inferred)*

PurpleSploit reference keys:

- **PØ** — no matching service module found in the complete `python/purplesploit/modules` inventory; modules are registered from Python files by path. *(measured; recorded: `python/purplesploit/core/framework.py:166-250@c962994`)*
- **PN** — generic Nmap module with selectable NSE script and scan operations, but no registered service-specific operation. *(recorded: `python/purplesploit/modules/recon/nmap.py:46-87,151-190@c962994`)*
- **PW** — generic HTTPx/Nuclei coverage: HTTP reachability, technology detection, template scanning, panels, misconfigurations, APIs, network templates, and default credentials. *(recorded: `python/purplesploit/modules/web/httpx.py:10-15,98-174@c962994`; `python/purplesploit/modules/recon/nuclei.py:16-22,121-206@c962994`)*
- **P-DNS** — `recon/dns`, including AXFR, record queries, reverse lookup, and parsed records. *(recorded: `python/purplesploit/modules/recon/dns.py:64-100,128-348@c962994`)*
- **P-HTTP** — HTTPx, Nuclei, Feroxbuster, Wfuzz, WPScan, and SQLMap modules. *(recorded: `python/purplesploit/modules/web/httpx.py:10-174`; `python/purplesploit/modules/recon/nuclei.py:16-206`; `python/purplesploit/modules/web/feroxbuster.py:54-69`; `python/purplesploit/modules/web/wfuzz.py:117-151@c962994`)*
- **P-KRB** — Kerbrute user enumeration plus Impacket AS-REP and Kerberoast modules. *(recorded: `python/purplesploit/modules/ad/kerbrute.py:101-124`; `python/purplesploit/modules/impacket/asreproast.py:1-28`; `python/purplesploit/modules/impacket/kerberoast.py:1-28@c962994`)*
- **P-LDAP** — thirteen NXC LDAP/BloodHound operations. *(recorded: `python/purplesploit/modules/network/nxc_ldap.py:76-196@c962994`)*
- **P-MSSQL** — authentication, version, database/table enumeration, privilege checking, and xp_cmdshell operations. *(recorded: `python/purplesploit/modules/network/nxc_mssql.py:45-114@c962994`)*
- **P-RDP** — authentication, domain/PTH authentication, and NLA checking. *(recorded: `python/purplesploit/modules/network/nxc_rdp.py:44-94@c962994`)*
- **P-SMB** — NXC’s forty-plus operations plus dedicated SMB enumeration and vulnerability modules. *(recorded: `python/purplesploit/modules/network/nxc_smb.py:71-139`; `python/purplesploit/modules/smb/enumeration.py:65-125`; `python/purplesploit/modules/smb/vulnerability.py:65-114@c962994`)*
- **P-SSH** — authentication and authenticated system, user, sudo, command, and network operations. *(recorded: `python/purplesploit/modules/network/nxc_ssh.py:42-91@c962994`)*
- **P-WINRM** — authentication and authenticated command/system/user/privilege operations. *(recorded: `python/purplesploit/modules/network/nxc_winrm.py:44-101@c962994`)*

| # | Aranum dispatcher | Status | PurpleSploit counterpart and basis |
|---:|---|---|---|
| 1 | `enum-activemq.sh` | partial | Aranum has OpenWire/Jolokia-specific probes; PurpleSploit has only PW. *(recorded: `aranumtoolkit/network/enum-activemq.sh:2-7@52f2fc0`; PW; inferred status)* |
| 2 | `enum-afp.sh` | partial | AFP server/share NSE checks versus PN only. *(recorded: `aranumtoolkit/network/enum-afp.sh:2-3@52f2fc0`; PN; inferred status)* |
| 3 | `enum-ajp.sh` | partial | AJP authentication/method/header checks versus PN only. *(recorded: `aranumtoolkit/network/enum-ajp.sh:2-8@52f2fc0`; PN; inferred status)* |
| 4 | `enum-artifact.sh` | partial | Product-specific Docker Registry, Nexus, Artifactory, and Harbor endpoints versus PW. *(recorded: `aranumtoolkit/network/enum-artifact.sh:2-5@52f2fc0`; PW; inferred status)* |
| 5 | `enum-backup.sh` | partial | Backup-product HTTP and protocol fingerprints versus PW/PN. *(recorded: `aranumtoolkit/network/enum-backup.sh:2-17@52f2fc0`; PW, PN; inferred status)* |
| 6 | `enum-bambu.sh` | missing | Multi-signal Bambu correlation has no PurpleSploit counterpart. *(recorded: `aranumtoolkit/network/enum-bambu.sh:2-5@52f2fc0`; PØ; inferred status)* |
| 7 | `enum-cassandra.sh` | partial | Cassandra-specific enumeration versus PN. *(recorded: `aranumtoolkit/network/enum-cassandra.sh:2-5@52f2fc0`; PN; inferred status)* |
| 8 | `enum-clickhouse.sh` | partial | ClickHouse SQL/HTTP checks versus PW. *(recorded: `aranumtoolkit/network/enum-clickhouse.sh:2-5@52f2fc0`; PW; inferred status)* |
| 9 | `enum-consul.sh` | partial | Consul API, catalog, KV, and ACL checks versus PW. *(recorded: `aranumtoolkit/network/enum-consul.sh:2-6@52f2fc0`; PW; inferred status)* |
| 10 | `enum-couchbase.sh` | partial | Couchbase pool/version/topology endpoints versus PW. *(recorded: `aranumtoolkit/network/enum-couchbase.sh:2-3@52f2fc0`; PW; inferred status)* |
| 11 | `enum-couchdb.sh` | partial | CouchDB database/configuration checks versus PW. *(recorded: `aranumtoolkit/network/enum-couchdb.sh:2-7@52f2fc0`; PW; inferred status)* |
| 12 | `enum-dns.sh` | overlap | Both implement AXFR and record enumeration; Aranum additionally runs `version.bind` and optional dnsrecon. *(recorded: `aranumtoolkit/network/enum-dns.sh:2,14-39@52f2fc0`; P-DNS; inferred status)* |
| 13 | `enum-docker.sh` | partial | Docker remote-API-specific exposure checks versus PW. *(recorded: `aranumtoolkit/network/enum-docker.sh:2-6@52f2fc0`; PW; inferred status)* |
| 14 | `enum-elastic.sh` | partial | Elasticsearch/Kibana-specific APIs versus PW. *(recorded: `aranumtoolkit/network/enum-elastic.sh:2-7@52f2fc0`; PW; inferred status)* |
| 15 | `enum-etcd.sh` | partial | etcd key/API checks versus PW. *(recorded: `aranumtoolkit/network/enum-etcd.sh:2-6@52f2fc0`; PW; inferred status)* |
| 16 | `enum-finger.sh` | missing | Finger user/session queries have no PurpleSploit counterpart. *(recorded: `aranumtoolkit/network/enum-finger.sh:2-3@52f2fc0`; PØ; inferred status)* |
| 17 | `enum-flexnet.sh` | missing | FLEXlm/vendor-daemon enumeration has no PurpleSploit counterpart. *(recorded: `aranumtoolkit/network/enum-flexnet.sh:2-6@52f2fc0`; PØ; inferred status)* |
| 18 | `enum-ftp.sh` | missing | PurpleSploit’s FTP auto-enum rule explicitly contains no module. *(recorded: `aranumtoolkit/network/enum-ftp.sh:2@52f2fc0`; `python/purplesploit/core/auto_enum.py:251-258@c962994+CWP1`; inferred status)* |
| 19 | `enum-git.sh` | missing | Git-daemon anonymous repository enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-git.sh:2-4@52f2fc0`; PØ; inferred status)* |
| 20 | `enum-hpc.sh` | partial | Slurm/HTCondor and related surfaces receive only generic PN/PW coverage. *(recorded: `aranumtoolkit/network/enum-hpc.sh:2-8@52f2fc0`; PN, PW; inferred status)* |
| 21 | `enum-http.sh` | overlap | Both have HTTPx/Nuclei and web discovery; Aranum additionally coordinates headers, WhatWeb, common-path validation, FFUF, and optional Nikto. *(recorded: `aranumtoolkit/network/enum-http.sh:2-15,150-230@52f2fc0`; P-HTTP; inferred status)* |
| 22 | `enum-https.sh` | overlap | Tracked alias to `enum-http.sh`; it shares P-HTTP coverage. *(measured alias; recorded: `aranumtoolkit/network/enum-http.sh:2-15@52f2fc0`; P-HTTP; inferred status)* |
| 23 | `enum-ike.sh` | partial | IKE-specific `ike-scan` behavior is absent; PN can supply only generic/custom-NSE portions. *(recorded: `aranumtoolkit/network/enum-ike.sh:2-7@52f2fc0`; PN; inferred status)* |
| 24 | `enum-imap.sh` | partial | IMAP capability/TLS checks versus PN only. *(recorded: `aranumtoolkit/network/enum-imap.sh:2-6@52f2fc0`; PN; inferred status)* |
| 25 | `enum-influxdb.sh` | partial | InfluxDB API-specific checks versus PW. *(recorded: `aranumtoolkit/network/enum-influxdb.sh:2-7@52f2fc0`; PW; inferred status)* |
| 26 | `enum-ipmi.sh` | partial | IPMI cipher/RAKP checks versus PN only. *(recorded: `aranumtoolkit/network/enum-ipmi.sh:2-7@52f2fc0`; PN; inferred status)* |
| 27 | `enum-ipp.sh` | partial | IPP/CUPS printer and admin checks versus generic PW/PN. *(recorded: `aranumtoolkit/network/enum-ipp.sh:2-6@52f2fc0`; PW, PN; inferred status)* |
| 28 | `enum-jabber.sh` | missing | XMPP stream, STARTTLS, SASL, registration, discovery, MUC, BOSH, and WebSocket enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-jabber.sh:2-16@52f2fc0`; PØ; inferred status)* |
| 29 | `enum-jmx.sh` | partial | JMX/RMI-specific enumeration versus PN only. *(recorded: `aranumtoolkit/network/enum-jmx.sh:2-7@52f2fc0`; PN; inferred status)* |
| 30 | `enum-kafka.sh` | missing | Kafka broker/topic metadata enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-kafka.sh:2-6@52f2fc0`; PØ; inferred status)* |
| 31 | `enum-kerberos.sh` | covered | P-KRB collectively covers user enumeration, AS-REP roasting, and Kerberoasting; Aranum adds automatic SMB/LDAP user-list correlation. *(recorded: `aranumtoolkit/network/enum-kerberos.sh:2,16-115@52f2fc0`; P-KRB; inferred status)* |
| 32 | `enum-kubernetes.sh` | partial | Kubernetes API/kubelet-specific checks versus PW. *(recorded: `aranumtoolkit/network/enum-kubernetes.sh:2-7@52f2fc0`; PW; inferred status)* |
| 33 | `enum-ldap.sh` | overlap | Both provide extensive LDAP/AD enumeration and BloodHound paths. *(recorded: `aranumtoolkit/network/enum-ldap.sh:2,17-175@52f2fc0`; P-LDAP; inferred status)* |
| 34 | `enum-mdns.sh` | partial | DNS-SD service-catalog discovery versus PN. *(recorded: `aranumtoolkit/network/enum-mdns.sh:2-6@52f2fc0`; PN; inferred status)* |
| 35 | `enum-memcached.sh` | partial | Memcached statistics/data-surface checks versus PN only. *(recorded: `aranumtoolkit/network/enum-memcached.sh:2-6@52f2fc0`; PN; inferred status)* |
| 36 | `enum-mongo.sh` | partial | MongoDB authentication/database checks versus PN only. *(recorded: `aranumtoolkit/network/enum-mongo.sh:2-8@52f2fc0`; PN; inferred status)* |
| 37 | `enum-monitoring.sh` | partial | Zabbix/Nagios/monitoring-product probes versus generic PW/PN. *(recorded: `aranumtoolkit/network/enum-monitoring.sh:2-8@52f2fc0`; PW, PN; inferred status)* |
| 38 | `enum-mqtt.sh` | missing | MQTT subscription/system-topic enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-mqtt.sh:2-6@52f2fc0`; PØ; inferred status)* |
| 39 | `enum-msrpc.sh` | partial | Endpoint-mapper enumeration is not implemented directly; PN and SMB/Impacket modules cover only adjacent functionality. *(recorded: `aranumtoolkit/network/enum-msrpc.sh:2-7@52f2fc0`; PN, P-SMB; inferred status)* |
| 40 | `enum-mssql.sh` | overlap | Both implement authentication, version and privilege checks; Aranum additionally probes SQL Browser dynamic instances and empty passwords. *(recorded: `aranumtoolkit/network/enum-mssql.sh:2,11-84@52f2fc0`; P-MSSQL; inferred status)* |
| 41 | `enum-mysql.sh` | partial | MySQL protocol/authentication enumeration versus PN; SQLMap is not a MySQL-service module. *(recorded: `aranumtoolkit/network/enum-mysql.sh:2-8@52f2fc0`; PN; inferred status)* |
| 42 | `enum-nats.sh` | partial | NATS protocol/monitoring endpoints versus PW only. *(recorded: `aranumtoolkit/network/enum-nats.sh:2-6@52f2fc0`; PW; inferred status)* |
| 43 | `enum-neo4j.sh` | partial | Neo4j HTTP/Bolt/default-credential checks versus PW. *(recorded: `aranumtoolkit/network/enum-neo4j.sh:2-8@52f2fc0`; PW; inferred status)* |
| 44 | `enum-netbios-ns.sh` | missing | UDP/137 name-table enumeration is not supplied by the SMB modules. *(recorded: `aranumtoolkit/network/enum-netbios-ns.sh:2-6@52f2fc0`; P-SMB; measured absence; inferred status)* |
| 45 | `enum-nfs.sh` | partial | Export, rpcinfo, and `no_root_squash` checks versus PN only. *(recorded: `aranumtoolkit/network/enum-nfs.sh:2@52f2fc0`; PN; inferred status)* |
| 46 | `enum-ntp.sh` | partial | Mode-6/mode-7 checks versus PN only. *(recorded: `aranumtoolkit/network/enum-ntp.sh:2-8@52f2fc0`; PN; inferred status)* |
| 47 | `enum-oracle.sh` | partial | TNS/SID enumeration versus PN only. *(recorded: `aranumtoolkit/network/enum-oracle.sh:2-7@52f2fc0`; PN; inferred status)* |
| 48 | `enum-platform.sh` | partial | Nomad, Portainer, Rancher, and Argo CD fingerprints versus PW. *(recorded: `aranumtoolkit/network/enum-platform.sh:2-4@52f2fc0`; PW; inferred status)* |
| 49 | `enum-pop3.sh` | partial | POP3 capability/plaintext/TLS checks versus PN. *(recorded: `aranumtoolkit/network/enum-pop3.sh:2-6@52f2fc0`; PN; inferred status)* |
| 50 | `enum-postgres.sh` | partial | PostgreSQL protocol/authentication checks versus PN. *(recorded: `aranumtoolkit/network/enum-postgres.sh:2-8@52f2fc0`; PN; inferred status)* |
| 51 | `enum-print.sh` | missing | PJL/JetDirect and LPD enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-print.sh:2-6@52f2fc0`; PØ; inferred status)* |
| 52 | `enum-rabbitmq.sh` | partial | RabbitMQ management API/default-credential checks versus PW. *(recorded: `aranumtoolkit/network/enum-rabbitmq.sh:2-6@52f2fc0`; PW; inferred status)* |
| 53 | `enum-radius.sh` | missing | RADIUS reachability/BlastRADIUS precondition checking has no counterpart. *(recorded: `aranumtoolkit/network/enum-radius.sh:2-7@52f2fc0`; PØ; inferred status)* |
| 54 | `enum-rdp.sh` | overlap | Both check authentication and NLA; Aranum also runs encryption, NTLM-info, MS12-020, screenshot, and `rdp-sec-check` paths. *(recorded: `aranumtoolkit/network/enum-rdp.sh:2,11-38@52f2fc0`; P-RDP; inferred status)* |
| 55 | `enum-redis.sh` | partial | Redis protocol/version/TLS/Sentinel checks versus generic PN/Nuclei coverage. *(recorded: `aranumtoolkit/network/enum-redis.sh:2@52f2fc0`; PN, PW; inferred status)* |
| 56 | `enum-rethinkdb.sh` | partial | RethinkDB admin/driver checks versus PW. *(recorded: `aranumtoolkit/network/enum-rethinkdb.sh:2-3@52f2fc0`; PW; inferred status)* |
| 57 | `enum-rsync.sh` | missing | Anonymous rsync-module enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-rsync.sh:2-6@52f2fc0`; PØ; inferred status)* |
| 58 | `enum-sip.sh` | partial | SIP/SIPS extension and method enumeration versus PN. *(recorded: `aranumtoolkit/network/enum-sip.sh:2-7@52f2fc0`; PN; inferred status)* |
| 59 | `enum-slp.sh` | partial | SLP discovery/amplification checks versus PN only. *(recorded: `aranumtoolkit/network/enum-slp.sh:2-7@52f2fc0`; PN; inferred status)* |
| 60 | `enum-smb.sh` | overlap | Both have deep SMB enumeration; Aranum combines NXC, enum4linux-ng, smbmap, rpcclient, NSE, and cross-service username harvesting. *(recorded: `aranumtoolkit/network/enum-smb.sh:2-3,14-128@52f2fc0`; P-SMB; inferred status)* |
| 61 | `enum-smtp.sh` | partial | SMTP EHLO, STARTTLS, user, and relay checks versus PN. *(recorded: `aranumtoolkit/network/enum-smtp.sh:2-3@52f2fc0`; PN; inferred status)* |
| 62 | `enum-snmp.sh` | partial | Community discovery and SNMP walking versus PN only. *(recorded: `aranumtoolkit/network/enum-snmp.sh:2@52f2fc0`; PN; inferred status)* |
| 63 | `enum-solr.sh` | partial | Solr admin/API/version checks versus PW. *(recorded: `aranumtoolkit/network/enum-solr.sh:2-7@52f2fc0`; PW; inferred status)* |
| 64 | `enum-squid.sh` | partial | Forward-proxy behavior checks versus generic PW. *(recorded: `aranumtoolkit/network/enum-squid.sh:2-4@52f2fc0`; PW; inferred status)* |
| 65 | `enum-ssdp.sh` | partial | SSDP M-SEARCH/UPnP checks versus PN only. *(recorded: `aranumtoolkit/network/enum-ssdp.sh:2-7@52f2fc0`; PN; inferred status)* |
| 66 | `enum-ssh.sh` | overlap | Both perform authentication; Aranum additionally owns banner, algorithm, authentication-method, OS, and CVE signal enumeration. *(recorded: `aranumtoolkit/network/enum-ssh.sh:2,49-164@52f2fc0`; P-SSH; inferred status)* |
| 67 | `enum-storage.sh` | partial | iSCSI, Ceph, Gluster, and MinIO checks versus generic PW/PN. *(recorded: `aranumtoolkit/network/enum-storage.sh:2-4@52f2fc0`; PW, PN; inferred status)* |
| 68 | `enum-telnet.sh` | partial | Telnet negotiation/banner checks versus PN. *(recorded: `aranumtoolkit/network/enum-telnet.sh:2-6@52f2fc0`; PN; inferred status)* |
| 69 | `enum-tftp.sh` | partial | TFTP filename/RRQ checks versus PN. *(recorded: `aranumtoolkit/network/enum-tftp.sh:2-3@52f2fc0`; PN; inferred status)* |
| 70 | `enum-unknown.sh` | partial | Aranum chains banner, HTTP/TLS, Nmap, and Nuclei handling; PurpleSploit has the same generic components but no equivalent unknown-service operation. *(recorded: `aranumtoolkit/network/enum-unknown.sh:2-7@52f2fc0`; PN, PW; inferred status)* |
| 71 | `enum-vault.sh` | partial | Vault seal, health, and initialization-state checks versus PW. *(recorded: `aranumtoolkit/network/enum-vault.sh:2-8@52f2fc0`; PW; inferred status)* |
| 72 | `enum-vnc.sh` | partial | VNC security, title, bypass, and banner checks versus PN. *(recorded: `aranumtoolkit/network/enum-vnc.sh:2-5@52f2fc0`; PN; inferred status)* |
| 73 | `enum-winrm.sh` | overlap | Both perform NXC authentication and authenticated command-based enumeration. *(recorded: `aranumtoolkit/network/enum-winrm.sh:2,11-31@52f2fc0`; P-WINRM; inferred status)* |
| 74 | `enum-x11.sh` | partial | X11 unauthenticated-display checks versus PN. *(recorded: `aranumtoolkit/network/enum-x11.sh:2-4@52f2fc0`; PN; inferred status)* |
| 75 | `enum-xmpp.sh` | missing | Tracked alias to `enum-jabber.sh`; PurpleSploit has no XMPP module. *(measured alias; recorded: `aranumtoolkit/network/enum-jabber.sh:2-16@52f2fc0`; PØ; inferred status)* |
| 76 | `enum-zookeeper.sh` | missing | ZooKeeper four-letter-word/configuration enumeration has no counterpart. *(recorded: `aranumtoolkit/network/enum-zookeeper.sh:2-8@52f2fc0`; PØ; inferred status)* |

Totals are 1 `covered`, 9 `overlap` paths representing eight canonical services, 52 `partial`, and 14 `missing`. *(measured from the matrix; inferred classifications)*

The ranking implication is breadth first: integrate the 14 missing services and Aranum’s product-specific portions of the 52 partial services through the common backend rather than creating new PurpleSploit service implementations. *(inferred)*

### Q9 — Registry shape

Use one PurpleSploit module, `recon/aranum`, with registered operations, not one Python module per dispatcher. *(inferred)* The current registry identity is a Python-file-derived module path, while granular selection is a separate operation dictionary resolved by name and executed through the common validation/audit path. *(recorded: `python/purplesploit/core/framework.py:166-250,255-290,338-373@c962994`; `python/purplesploit/core/module.py:441-460@c962994`)*

CWP1 already represents an auto-enum step as `module_path + operation`, performs case-insensitive operation lookup, and incorporates both into its execution key. *(recorded: `python/purplesploit/core/auto_enum.py:37-52,464-481,613-625,905-959@c962994+CWP1`)* Therefore the actual lookup should be:

- module path: `recon/aranum`
- operation: canonical service slug such as `smb`, `ldap`, or `activemq`
- displayed/execution identity: `recon/aranum:smb`

*(inferred)*

Do not register 76 independent Python modules, because that would duplicate process construction, options, version checks, import logic, and output handling 76 times. *(inferred)* Register 74 canonical dispatcher operations, normalize `https → http` and `xmpp → jabber`, and optionally show the aliases in UI search without creating duplicate handlers. *(measured alias count; inferred design)*

Add one coarse `Run Selected Services` operation that passes the selected service set to Aranum once. *(inferred)* Direct operator selection can target a single canonical service, but AutoEnum should coalesce endpoints/services from one discovery result into one Aranum process rather than launching one process per endpoint-rule match. *(inferred)* Aranum already owns bounded host and service concurrency and accepts `--only`, `-P`, and `--service-parallel`. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh:63-69,143-153,179-183@52f2fc0`)*

### Q10 — Overlap ownership

Aranum should own baseline enumeration recipes, dispatcher evolution, evidence files, and enumeration finding classification for every overlapping service; PurpleSploit should own orchestration, normalized storage, correlation, reporting, and explicit specialist/post-enumeration actions. *(inferred)* Existing PurpleSploit modules remain available for direct operator use, but AutoEnum should stop growing separate baseline recipes for the same services. *(inferred)*

| Service | Enumeration authority | PurpleSploit-owned specialist boundary |
|---|---|---|
| SMB | Aranum: NXC, enum4linux-ng, smbmap, anonymous RPC, NSE, relay signals, and cross-service user harvesting. *(recorded: `aranumtoolkit/network/enum-smb.sh:14-128@52f2fc0`; inferred ownership)* | Authenticated share interaction, explicit file transfer, execution, credential dumping, and manually selected vulnerability operations remain PurpleSploit modules. *(recorded: `python/purplesploit/modules/network/nxc_smb.py:87-139@c962994`; inferred ownership)* |
| LDAP | Aranum: RootDSE, LDAP records, NXC, roasting, BloodHound, Certipy, and delegation enumeration. *(recorded: `aranumtoolkit/network/enum-ldap.sh:17-175@52f2fc0`; inferred ownership)* | Direct authenticated LDAP/BloodHound operations remain available in PurpleSploit. *(recorded: `python/purplesploit/modules/network/nxc_ldap.py:76-196@c962994`; inferred ownership)* |
| WinRM | Aranum: endpoint/authentication enumeration and its recorded evidence. *(recorded: `aranumtoolkit/network/enum-winrm.sh:11-31@52f2fc0`; inferred ownership)* | Explicit authenticated command, PowerShell, system, user, and privilege actions remain PurpleSploit-owned specialist operations. *(recorded: `python/purplesploit/modules/network/nxc_winrm.py:44-101@c962994`; inferred ownership)* |
| RDP | Aranum: encryption, NLA, NTLM information, MS12-020, and `rdp-sec-check` enumeration. *(recorded: `aranumtoolkit/network/enum-rdp.sh:11-38@52f2fc0`; inferred ownership)* | Explicit credential/PTH operations remain PurpleSploit-owned. *(recorded: `python/purplesploit/modules/network/nxc_rdp.py:44-94@c962994`; inferred ownership)* |
| SSH | Aranum: banner, algorithms, authentication methods, OS classification, and CVE signals. *(recorded: `aranumtoolkit/network/enum-ssh.sh:49-164@52f2fc0`; inferred ownership)* | Explicit authenticated command, sudo, system, user, and network inspection remains PurpleSploit-owned. *(recorded: `python/purplesploit/modules/network/nxc_ssh.py:42-91@c962994`; inferred ownership)* |
| MSSQL | Aranum: service/empty-password checks, SQL Browser dynamic instances, authentication, version, and baseline privilege posture. *(recorded: `aranumtoolkit/network/enum-mssql.sh:11-84@52f2fc0`; inferred ownership)* | Explicit database/table exploration and operator-selected xp_cmdshell actions remain PurpleSploit-owned. *(recorded: `python/purplesploit/modules/network/nxc_mssql.py:45-114@c962994`; inferred ownership)* |
| DNS | Aranum: scheduled AXFR, `version.bind`, standard records, and dnsrecon breadth. *(recorded: `aranumtoolkit/network/enum-dns.sh:14-39@52f2fc0`; inferred ownership)* | PurpleSploit retains direct record-query operations and can reuse its existing structured record parser when projecting imported results. *(recorded: `python/purplesploit/modules/recon/dns.py:64-100,128-348@c962994`; inferred ownership)* |
| HTTP | Aranum: scheduled web enumeration and tool-chain defaults across HTTPx, WhatWeb, headers, validated paths, Nuclei, FFUF, and optional Nikto. *(recorded: `aranumtoolkit/network/enum-http.sh:2-15,150-230@52f2fc0`; inferred ownership)* | PurpleSploit retains direct HTTPx/Nuclei/Feroxbuster/Wfuzz/WPScan/SQLMap operations for deliberate specialist use. *(recorded: P-HTTP; inferred ownership)* |

Result fidelity favors Aranum for baseline enumeration because its report collector converts dispatcher evidence into structured findings, coverage, diagnostics, and posture outputs. *(recorded: `aranumtoolkit/network/report.py:1622-1808,1813-2054,2704-2778,2820-2914@52f2fc0`)* PurpleSploit has structured parsers for DNS, HTTPx, and Nuclei, while the six NXC network modules return tool results without service-specific `parse_output` implementations. *(measured; recorded: `python/purplesploit/modules/recon/dns.py:341-348`; `python/purplesploit/modules/web/httpx.py:146-174`; `python/purplesploit/modules/recon/nuclei.py:330-440@c962994`)*

### Q11 — Invocation contract

Agree with preserving Aranum’s default option values and requiring every opt-in flag to originate from an explicit operator option; disagree with calling the current behavior uniformly “enumeration-only” and with exposing `--write`/`--exploit`/`--rce` through the ordinary `aranum run` operation. *(inferred)*

`auto-enum.sh` accepts the explicitly gated `--ike`, `--slp`, `--ntp`, `--ssdp`, `--radius`, and `--aggressive` options and leaves them disabled by default. *(recorded: `aranumtoolkit/network/auto-enum.sh:99-117,164-169@52f2fc0`)* Auto-enum rules and workflow templates must never add those flags. *(inferred)* `--desktop-ok` belongs to the separate local-access path. *(recorded: `/srv/share/dev/aranum/aranum.py:85-101@52f2fc0`; `aranumtoolkit/network/local-enum.py:1122-1136@52f2fc0`)*

`--write`, `--exploit`, and `--rce` are not accepted `auto-enum.sh` options; unknown options exit with an error. *(recorded: `aranumtoolkit/network/auto-enum.sh:140-172@52f2fc0`)* Any future standalone exploit integration therefore needs a separately named specialist operation, not arbitrary pass-through on the enumeration operation. *(inferred)*

The default is non-writing, but credentialed defaults can perform remote commands and screenshots: WinRM runs `whoami /priv`, MSSQL runs `xp_cmdshell` with `whoami`, and RDP requests screenshots when credentials are supplied. *(recorded: `aranumtoolkit/network/enum-winrm.sh:19-22`; `aranumtoolkit/network/enum-mssql.sh:70-77`; `aranumtoolkit/network/enum-rdp.sh:18-30@52f2fc0`)* The UI and execution record should describe those current Aranum semantics accurately; this is interface fidelity, not an authorization or safety-hardening stage moved before S19. *(inferred)*

I also disagree that the current unified CLI writes only to an explicit `-o` directory: `aranum.py run` creates `outputs/<session>/{raw,inputs,reports}` before honoring an explicit raw-output path and copies the input into the session tree. *(recorded: `/srv/share/dev/aranum/aranum.py:179-219,725-737@52f2fc0`)* Until Aranum offers a strict single-root mode, Option D should invoke `auto-enum.sh -i <scan> -o <operator-dir>` and `report.py <operator-dir>` directly with argv arrays, or document the additional session tree. *(inferred)*

### Q12 — KB placement

Aranum should remain the sole KB author; PurpleSploit should consume a run-pinned inline KB subset or equivalent `kb-snapshot.json`, not vendor a second mutable copy. *(inferred)* The current KB has schema `1` and separates categories, service mappings, finding classes, and checks, but it does not identify an Aranum release or content digest. *(recorded: `aranumtoolkit/network/finding-kb.json:1-79@52f2fc0`; measured)*

The preferred bundle contract is:

- inline only the referenced classes/checks;
- record KB schema, Aranum version, and KB digest;
- preserve the complete inline objects in observation provenance;
- allow an exact bundled snapshot as an equivalent representation.

*(inferred)*

Reading the installed Aranum KB should be a compatibility fallback only when the bundle declares the expected version/digest; silently enriching an old result with the newest installed KB would make report meaning time-dependent. *(inferred)* A bundle must remain importable without Aranum installed. *(inferred)*

Report projection should be:

- source finding `line` → Description;
- KB `why` → Impact;
- KB `fix[]` → Remediation;
- KB `refs[]` → References;
- KB `test[]` → a visibly labelled “Validation / retest” subsection;
- visible source note → `Aranum KB <version>, <kb_id>, digest <…>`.

*(inferred)*

The current core finding already has Description, Impact, Remediation, References, Evidence, and Proof-of-Concept fields, while current Markdown/HTML/XLSX reporting renders Impact and Remediation but has no dedicated validation field. *(recorded: `python/purplesploit/core/findings.py:83-130`; `python/purplesploit/reporting/models.py:100-142`; `python/purplesploit/reporting/markdown.py:262-310`; `python/purplesploit/reporting/html.py:171-175`; `python/purplesploit/reporting/xlsx.py:260-266@c962994`)* Until CWP7 adds a first-class validation field, render KB tests under a `Validation / retest` heading inside the remediation projection and preserve the structured list in raw provenance. *(inferred)* Do not overwrite operator-authored text during re-import; keep source synopsis, KB guidance, and operator additions distinguishable. *(inferred)*

### Q13 — Benefit harness

The four proposed themes are directionally correct, with three measurement corrections. *(inferred)*

1. Measure exact `(host, transport, port, service)` endpoint coverage and canonical dispatcher operations, not only service categories per host; categories can hide TCP/UDP identity and zero-finding endpoints. *(inferred)*
2. Use findings with a resolvable `kb_id` as the guidance denominator, and measure `why`, `fix`, and `test` fidelity separately. *(inferred)*
3. Separate KB catalog availability from checks actually executed per host; PASS, FAIL, WARN, INFO, NA, and ERR must retain their distinct meanings. *(inferred)*
4. Keep the idempotency metric, but define success as zero new source identities on exact re-import while still recording a successful import event or `last_seen` update. *(inferred)*

The missing acceptance metrics are:

| Metric | Acceptance criterion |
|---|---|
| Registry completeness | All 74 canonical dispatcher operations resolve through `recon/aranum`; `https` and `xmpp` resolve to their canonical aliases; selection can be tested without starting Aranum. *(inferred)* |
| Inventory fidelity | Every fixture endpoint, including zero-finding endpoints and TCP/UDP same-number ports, round-trips with host, port, transport, service, version, and hostname unchanged. *(inferred)* |
| Finding fidelity | Expected finding count, severity, scope, `rule_id`, `kb_id`, source ID, evidence paths, and raw source object match a frozen oracle. *(inferred)* |
| Observation fidelity | Every posture and coverage record imports once with its original status, subject, observed host, and domain `observed_from` relationship. *(inferred)* |
| Provenance | Every imported record has `source_tool`, tool version, schema, source ID, run ID, observation time, and raw or artifact reference. *(inferred)* |
| KB enrichment | 100% of records whose inline snapshot contains their `kb_id` receive the expected impact, remediation, validation, and references; unknown IDs remain importable without invented guidance. *(inferred)* |
| Exact re-import | Second import creates zero new findings, observations, targets, or services. *(inferred)* |
| New-run semantics | A different run ID retains a new observation occurrence while source-identity dedup prevents duplicate logical findings. *(inferred)* |
| Partial/error behavior | `partial`, top-level `errors`, ERR checks, unresolved artifacts, and redacted paths remain visible and do not turn into successful coverage. *(inferred)* |
| AutoEnum handoff | Imported endpoints produce the expected follow-up plan without another discovery scan and without duplicate Aranum/HTTPx/Nmap scheduling. *(inferred)* |
| Offline portability | The bundle imports and renders with Aranum absent from `PATH` and without reading its installation tree. *(inferred)* |
| Invocation discipline | A fake process runner proves default templates add no aggressive, local-desktop, write, exploit, or RCE flags and place `-o` at the operator-selected root. *(inferred)* |
| Report rendering | Markdown, HTML, and XLSX visibly distinguish source evidence, KB guidance, validation steps, and operator text. *(inferred)* |

Use at least three committed fixture bundles: network inventory, mixed Linux/Windows/AD posture, and partial/error/redacted output. *(inferred)* Aranum’s existing `all-services.xml` contains 14 hosts and 35 open ports and is suitable for routing/inventory expectations, while the bulk/posture fixtures cover Linux, Windows, and AD statuses. *(recorded: `aranumtoolkit/tests/test_nmap_parse.py:275-278`; `aranumtoolkit/tests/test_bulk_enum_report.py:59-91`; `aranumtoolkit/tests/test_host_posture.py:196-281,677-679@52f2fc0`)*

No checked-in fixture currently combines `findings.json` v2, `posture.json` v1, complete inventory, and an inline KB snapshot as one portable bundle. *(measured)* That portable synthetic bundle is the minimal additional Aranum fixture needed before the before/after harness can exercise Option A without generating data or touching a target. *(inferred)*