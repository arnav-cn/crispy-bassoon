# Decoder -> rules dependency

4.9.2 decoder, the rules that depend on it, and the WCS target of every
field it produces.

| 4.x decoder | product | file | blocks | rules | inherited | fields produced |
|---|---|---|---|---|---|---|
| `auditd-execve` | auditd-custom | auditd_decoders.xml | 9 | 47 | 46 | 10 |
| `sysmon-linux` | windows-rules-custom | decoder-linux-sysmon.xml | 0 | 11 | 10 | 0 |
| `auditd-path` | auditd-custom | auditd_decoders.xml | 1 | 9 | 8 | 10 |
| `network_switch` | perf-metrics | local_decoder.xml | 0 | 8 | 7 | 0 |
| `auditd-syscall` | auditd-custom | auditd_decoders.xml | 5 | 6 | 5 | 21 |
| `CEF` | maltrail-custom | maltrail_decoders.xml | 1 | 4 | 3 | 13 |
| `general_health_check` | perf-metrics | local_decoder.xml | 0 | 4 | 3 | 0 |
| `yara` | yara-custom | yara_decoders.xml | 1 | 4 | 3 | 3 |
| `naxsi-opnsense-parent` | naxsi-opnsense-custom | naxsi-opnsense_decoders.xml | 0 | 3 | 2 | 0 |
| `auditd-user_and_cred` | auditd-custom | auditd_decoders.xml | 7 | 2 | 1 | 11 |
| `auditd-config_change` | auditd-custom | auditd_decoders.xml | 7 | 1 | 0 | 8 |
| `auditd-cwd` | auditd-custom | auditd_decoders.xml | 1 | 1 | 0 | 2 |
| `auditd-proctitle` | auditd-custom | auditd_decoders.xml | 1 | 1 | 0 | 2 |
| `cpu_usage` | perf-metrics | custom_decoders.xml | 1 | 1 | 0 | 1 |
| `disk_check` | perf-metrics | local_decoder.xml | 0 | 1 | 0 | 0 |
| `disk_usage` | perf-metrics | custom_decoders.xml | 1 | 1 | 0 | 1 |
| `load_average_check` | perf-metrics | local_decoder.xml | 0 | 1 | 0 | 0 |
| `memory_check` | perf-metrics | local_decoder.xml | 0 | 1 | 0 | 0 |
| `parsed_processes` | perf-metrics | custom_decoders.xml | 1 | 1 | 0 | 6 |
| `ram_usage` | perf-metrics | custom_decoders.xml | 1 | 1 | 0 | 1 |
| `top_processes` | perf-metrics | custom_decoders.xml | 2 | 1 | 0 | 1 |
| `disk_check1` | perf-metrics | local_decoder.xml | 1 | 0 | 0 | 2 |
| `general_health_check1` | perf-metrics | local_decoder.xml | 1 | 0 | 0 | 3 |
| `load_average_check1` | perf-metrics | local_decoder.xml | 1 | 0 | 0 | 3 |
| `local_decoder_example` | perf-metrics | local_decoder.xml | 0 | 0 | 0 | 0 |
| `memory_check1` | perf-metrics | local_decoder.xml | 1 | 0 | 0 | 2 |
| `naxsi-opnsense-child` | naxsi-opnsense-custom | naxsi-opnsense_decoders.xml | 7 | 0 | 0 | 13 |
| `oid_snmp_decoder` | snmp-custom | oid_snmp_decoder.xml | 1 | 0 | 0 | 3 |
| `oid_snmp_decoder_fields` | snmp-custom | oid_snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `oid_snmp_decoder_session` | snmp-custom | oid_snmp_decoder.xml | 0 | 0 | 0 | 0 |
| `process_entry` | perf-metrics | custom_decoders.xml | 1 | 0 | 0 | 2 |
| `resource_monitor` | perf-metrics | custom_decoders.xml | 1 | 0 | 0 | 1 |
| `siem-authd` | wazuh-generic-1 | decoder-manager-logs.xml | 0 | 0 | 0 | 0 |
| `siem-authd-duplicate` | wazuh-generic-1 | decoder-manager-logs.xml | 1 | 0 | 0 | 2 |
| `snmptrap` | snmp-custom | snmp_decoder.xml | 0 | 0 | 0 | 0 |
| `snmptrap-device-ip` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `snmptrap-header` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 4 |
| `snmptrap-login-result` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `snmptrap-login-type` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `snmptrap-login-user` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `snmptrap-oid` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `snmptrap-session-type` | snmp-custom | snmp_decoder.xml | 1 | 0 | 0 | 1 |
| `sysmon-linux-child` | windows-rules-custom | decoder-linux-sysmon.xml | 57 | 0 | 0 | 57 |

## Fields produced by each decoder

| 4.x decoder | 4.x field | WCS target | source | in WCS schema |
|---|---|---|---|---|
| `auditd-execve` | `audit.argc` | process.args_count | decoder-map | yes |
| `auditd-execve` | `audit.execve.a0` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a1` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a2` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a3` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a4` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a5` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a6` | process.args | rule-map | yes |
| `auditd-execve` | `audit.execve.a7` | process.args | rule-map | yes |
| `auditd-execve` | `audit.id` | labels | decoder-map | n/a |
| `auditd-path` | `audit.directory.dev` | _(none, rides in labels)_ | - | - |
| `auditd-path` | `audit.directory.inode` | file.inode | decoder-map | yes |
| `auditd-path` | `audit.directory.mode` | file.mode | decoder-map | yes |
| `auditd-path` | `audit.directory.name` | event.action | rule-map | yes |
| `auditd-path` | `audit.directory.nametype` | event.action | rule-map | yes |
| `auditd-path` | `audit.id` | labels | decoder-map | n/a |
| `auditd-path` | `audit.item` | labels | decoder-map | n/a |
| `auditd-path` | `audit.ogid` | file.gid | decoder-map | yes |
| `auditd-path` | `audit.ouid` | file.uid | decoder-map | yes |
| `auditd-path` | `audit.rdev` | file.device | decoder-map | yes |
| `auditd-syscall` | `audit.arch` | host.architecture | decoder-map | yes |
| `auditd-syscall` | `audit.auid` | user.id | decoder-map | yes |
| `auditd-syscall` | `audit.command` | event.action | rule-map | yes |
| `auditd-syscall` | `audit.egid` | user.effective.group.id | decoder-map | yes |
| `auditd-syscall` | `audit.euid` | user.effective.id | decoder-map | yes |
| `auditd-syscall` | `audit.exe` | event.action | rule-map | yes |
| `auditd-syscall` | `audit.exit` | process.exit_code | decoder-map | yes |
| `auditd-syscall` | `audit.fsgid` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.fsuid` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.gid` | user.group.id | decoder-map | yes |
| `auditd-syscall` | `audit.id` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.key` | event.action | rule-map | yes |
| `auditd-syscall` | `audit.pid` | process.pid | decoder-map | yes |
| `auditd-syscall` | `audit.ppid` | process.parent.pid | decoder-map | yes |
| `auditd-syscall` | `audit.session` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.sgid` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.success` | event.outcome | decoder-map | yes |
| `auditd-syscall` | `audit.suid` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.syscall` | event.action | decoder-map | yes |
| `auditd-syscall` | `audit.tty` | labels | decoder-map | n/a |
| `auditd-syscall` | `audit.uid` | user.id | decoder-map | yes |
| `CEF` | `application` | service.name | decoder-map | yes |
| `CEF` | `category` | event.category | decoder-map | yes |
| `CEF` | `code` | event.code | decoder-map | yes |
| `CEF` | `date` | labels | decoder-map | n/a |
| `CEF` | `dstip` | destination.ip | decoder-map | yes |
| `CEF` | `dstport` | destination.port | decoder-map | yes |
| `CEF` | `ref` | labels | decoder-map | n/a |
| `CEF` | `severity` | event.severity | rule-map | yes |
| `CEF` | `srcip` | source.ip | decoder-map | yes |
| `CEF` | `srcport` | source.port | decoder-map | yes |
| `CEF` | `trail` | labels | decoder-map | n/a |
| `CEF` | `type` | event.action | rule-map (audit.type) | yes |
| `CEF` | `version` | labels | decoder-map | n/a |
| `yara` | `file` | file.path | decoder-map | yes |
| `yara` | `yara_info` | labels | decoder-map | n/a |
| `yara` | `yara_metadata` | labels | decoder-map | n/a |
| `auditd-user_and_cred` | `audit.acct` | user.name | decoder-map | yes |
| `auditd-user_and_cred` | `audit.auid` | user.id | decoder-map | yes |
| `auditd-user_and_cred` | `audit.exe` | event.action | rule-map | yes |
| `auditd-user_and_cred` | `audit.id` | labels | decoder-map | n/a |
| `auditd-user_and_cred` | `audit.pid` | process.pid | decoder-map | yes |
| `auditd-user_and_cred` | `audit.session` | labels | decoder-map | n/a |
| `auditd-user_and_cred` | `audit.subj` | labels | decoder-map | n/a |
| `auditd-user_and_cred` | `audit.type` | event.action | rule-map | yes |
| `auditd-user_and_cred` | `audit.uid` | user.id | decoder-map | yes |
| `auditd-user_and_cred` | `audit.unit` | event.action | rule-map | yes |
| `auditd-user_and_cred` | `srcip` | source.ip | decoder-map | yes |
| `auditd-config_change` | `audit.auid` | user.id | decoder-map | yes |
| `auditd-config_change` | `audit.id` | labels | decoder-map | n/a |
| `auditd-config_change` | `audit.key` | event.action | rule-map | yes |
| `auditd-config_change` | `audit.list` | labels | decoder-map | n/a |
| `auditd-config_change` | `audit.op` | event.action | decoder-map | yes |
| `auditd-config_change` | `audit.res` | event.outcome | decoder-map | yes |
| `auditd-config_change` | `audit.session` | labels | decoder-map | n/a |
| `auditd-config_change` | `audit.subj` | labels | decoder-map | n/a |
| `auditd-cwd` | `audit.cwd` | process.working_directory | decoder-map | yes |
| `auditd-cwd` | `audit.id` | labels | decoder-map | n/a |
| `auditd-proctitle` | `audit.id` | labels | decoder-map | n/a |
| `auditd-proctitle` | `audit.proctitle` | process.title | decoder-map | yes |
| `cpu_usage` | `cpu_usage` | host.cpu.usage | decoder-map | yes |
| `disk_usage` | `disk_usage` | labels | decoder-map | n/a |
| `parsed_processes` | `%CPU` | labels | decoder-map | n/a |
| `parsed_processes` | `%MEM` | labels | decoder-map | n/a |
| `parsed_processes` | `COMMAND` | event.action | rule-map (audit.command) | yes |
| `parsed_processes` | `PID` | process.pid | decoder-map | yes |
| `parsed_processes` | `TIME+` | labels | decoder-map | n/a |
| `parsed_processes` | `USER` | user.name | decoder-map | yes |
| `ram_usage` | `ram_usage` | host.memory.used.percentage | decoder-map | yes |
| `top_processes` | `top_processes` | labels | decoder-map | n/a |
| `disk_check1` | `disk_free_bytes` | labels | decoder-map | n/a |
| `disk_check1` | `disk_used_bytes` | labels | decoder-map | n/a |
| `general_health_check1` | `cpu_usage_%` | host.cpu.usage | decoder-map | yes |
| `general_health_check1` | `disk_usage_%` | labels | decoder-map | n/a |
| `general_health_check1` | `memory_usage_%` | host.memory.used.percentage | decoder-map | yes |
| `load_average_check1` | `15mins_loadAverage` | labels | decoder-map | n/a |
| `load_average_check1` | `1min_loadAverage` | labels | decoder-map | n/a |
| `load_average_check1` | `5mins_loadAverage` | labels | decoder-map | n/a |
| `memory_check1` | `memory_available_bytes` | host.memory.free | decoder-map | yes |
| `memory_check1` | `memory_used_bytes` | host.memory.used | decoder-map | yes |
| `naxsi-opnsense-child` | `blocked_requests` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `mode` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `naxsi_version` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `processed_requests` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `referrer` | http.request.referrer | decoder-map | yes |
| `naxsi-opnsense-child` | `request` | url.original | decoder-map | yes |
| `naxsi-opnsense-child` | `rule_id` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `score` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `score_tag` | labels | decoder-map | n/a |
| `naxsi-opnsense-child` | `server` | server.address | decoder-map | yes |
| `naxsi-opnsense-child` | `srcip` | source.ip | decoder-map | yes |
| `naxsi-opnsense-child` | `uri` | url.original | decoder-map | yes |
| `naxsi-opnsense-child` | `zone` | labels | decoder-map | n/a |
| `oid_snmp_decoder` | `engine_id` | labels | decoder-map | n/a |
| `oid_snmp_decoder` | `location` | labels | decoder-map | n/a |
| `oid_snmp_decoder` | `srcuser` | user.name | decoder-map | yes |
| `oid_snmp_decoder_fields` | `oid` | labels | decoder-map | n/a |
| `process_entry` | `process_memory` | labels | decoder-map | n/a |
| `process_entry` | `process_name` | process.name | decoder-map | yes |
| `resource_monitor` | `timestamp` | @timestamp | rule-map | yes |
| `siem-authd-duplicate` | `agent_id` | labels | decoder-map | n/a |
| `siem-authd-duplicate` | `duplicate_name` | labels | decoder-map | n/a |
| `snmptrap-device-ip` | `device_ip` | destination.ip | decoder-map | yes |
| `snmptrap-header` | `engine_id` | labels | decoder-map | n/a |
| `snmptrap-header` | `snmp_user` | user.name | decoder-map | yes |
| `snmptrap-header` | `snmp_version` | labels | decoder-map | n/a |
| `snmptrap-header` | `srcip` | source.ip | decoder-map | yes |
| `snmptrap-login-result` | `login_result` | event.outcome | decoder-map | yes |
| `snmptrap-login-type` | `login_type` | event.action | decoder-map | yes |
| `snmptrap-login-user` | `login_user` | user.name | decoder-map | yes |
| `snmptrap-oid` | `trap_oid` | labels | decoder-map | n/a |
| `snmptrap-session-type` | `session_type` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.DestinationIp` | destination.ip | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.archived` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.commandLine` | process.command_line | rule-map (win.eventdata.commandline) | yes |
| `sysmon-linux-child` | `eventdata.company` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.configuration` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.configurationFileHash` | file.hash.sha256 | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.creationUtcTime` | file.created | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.currentDirectory` | process.working_directory | rule-map (win.eventdata.currentdirectory) | yes |
| `sysmon-linux-child` | `eventdata.description` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.destinationHostname` | destination.domain | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.destinationIsIpv6` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.destinationPort` | destination.port | rule-map (win.eventdata.destinationport) | yes |
| `sysmon-linux-child` | `eventdata.destinationPortName` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.device` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.fileVersion` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.hashes` | file.hash.sha256 | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.image` | process.executable | rule-map (win.eventdata.image) | yes |
| `sysmon-linux-child` | `eventdata.initiated` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.integrityLevel` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.isExecutable` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.logonGuid` | user.id | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.logonId` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.originalFileName` | file.name | rule-map (win.eventdata.originalfilename) | yes |
| `sysmon-linux-child` | `eventdata.parentCommandLine` | process.parent.command_line | rule-map (win.eventdata.parentcommandline) | yes |
| `sysmon-linux-child` | `eventdata.parentImage` | process.parent.executable | rule-map (win.eventdata.parentimage) | yes |
| `sysmon-linux-child` | `eventdata.parentProcessGuid` | process.parent.entity_id | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.parentProcessId` | process.parent.pid | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.parentUser` | user.target.name | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.processGuid` | process.entity_id | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.processId` | process.pid | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.product` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.protocol` | network.protocol | rule-map (win.eventdata.protocol) | yes |
| `sysmon-linux-child` | `eventdata.ruleName` | rule.name | rule-map (win.eventdata.rulename) | yes |
| `sysmon-linux-child` | `eventdata.schemaVersion` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.sourceHostname` | source.domain | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.sourceIp` | source.ip | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.sourceIsIpv6` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.sourcePort` | source.port | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.sourcePortName` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.state` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.targetFilename` | file.path | rule-map (win.eventdata.targetfilename) | yes |
| `sysmon-linux-child` | `eventdata.terminalSessionId` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `eventdata.user` | user.name | rule-map (win.eventdata.user) | yes |
| `sysmon-linux-child` | `eventdata.utcTime` | event.created | decoder-map | yes |
| `sysmon-linux-child` | `eventdata.version` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `system.channel` | log.syslog.appname | rule-map (win.system.channel) | yes |
| `sysmon-linux-child` | `system.computer` | host.name | decoder-map | yes |
| `sysmon-linux-child` | `system.eventID` | event.code | rule-map | yes |
| `sysmon-linux-child` | `system.eventRecordID` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `system.keywords` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `system.level` | event.severity | decoder-map | yes |
| `sysmon-linux-child` | `system.opcode` | event.action | decoder-map | yes |
| `sysmon-linux-child` | `system.processID` | process.pid | decoder-map | yes |
| `sysmon-linux-child` | `system.systemTime` | event.created | decoder-map | yes |
| `sysmon-linux-child` | `system.task` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `system.threadID` | labels | decoder-map | n/a |
| `sysmon-linux-child` | `system.version` | labels | decoder-map | n/a |

## Fields the dependent rules match on

### `auditd-execve` (auditd-custom) - 47 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `audit.execve.a0` | 35 | process.args |
| `audit.execve.a1` | 30 | process.args |
| `audit.execve.a2` | 15 | process.args |
| `audit.execve.a3` | 10 | process.args |
| `audit.execve.a4` | 4 | process.args |
| `audit.execve.a5` | 1 | process.args |
| `audit.execve.a6` | 1 | process.args |
| `audit.execve.a7` | 1 | process.args |

### `sysmon-linux` (windows-rules-custom) - 11 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `system.eventID` | 8 | event.code |
| `eventdata.image` | 3 | process.executable |

### `auditd-path` (auditd-custom) - 9 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `audit.directory.name` | 7 | event.action |
| `audit.directory.nametype` | 1 | event.action |

### `auditd-syscall` (auditd-custom) - 6 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `audit.exe` | 3 | event.action |
| `audit.command` | 2 | event.action |
| `audit.key` | 1 | event.action |

### `CEF` (maltrail-custom) - 4 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `severity` | 3 | event.severity |

### `general_health_check` (perf-metrics) - 4 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `cpu_usage_%` | 1 | host.cpu.usage |
| `disk_usage_%` | 1 | labels |
| `memory_usage_%` | 1 | host.memory.used.percentage |

### `yara` (yara-custom) - 4 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `error_message` | 1 | _(none)_ |
| `warning_message` | 1 | _(none)_ |
| `yara_info` | 1 | labels |

### `naxsi-opnsense-parent` (naxsi-opnsense-custom) - 3 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `mode` | 2 | labels |

### `auditd-user_and_cred` (auditd-custom) - 2 rules

| 4.x field | rule uses | WCS target |
|---|---|---|
| `audit.unit` | 1 | event.action |

