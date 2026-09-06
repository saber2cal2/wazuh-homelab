# Monitor the Monitor — Detecting Silent Failure of a Network Sensor

A Wazuh-based staleness alert that fires when a Zeek network sensor stops
writing logs. Built after a real incident: a Zeek instance died and ran dead
for **28 days** before being discovered by accident. This closes that gap —
silent sensor death now raises a high-severity alert within minutes.

> **Why this exists:** auto-restart watchdogs *fix* a crashed sensor, but
> nothing *tells you* when it fails. A dead process can't report its own
> death. The answer is to watch for the **absence of freshness** — if the
> sensor's logs stop advancing, that silence is the alert.

---

## 1. The problem: silent failures

Security controls fail in two ways:

- **Loud failure** — the process errors, exits, logs a crash. You notice.
- **Silent failure** — the process dies or wedges and simply stops producing
  output. Nothing errors. Dashboards look normal because no *new* bad events
  arrive. You don't notice — sometimes for weeks.

Silent failure is the dangerous one, and it's especially insidious for
*monitoring* tools: the thing that's supposed to notice problems is itself
the thing that failed, so it can't notice its own failure.

The general principle, applicable to any always-on process that should
continuously produce output:

```
Don't wait for an error message that will never come.
Watch whether the output keeps advancing. Absence of freshness = failure.
```

This is the **heartbeat / staleness** pattern.

---

## 2. Architecture

Reuses a standard Wazuh detection pipeline (agent → decoder → rule → alert),
with one added piece: a small script that *generates* a freshness signal.

```
[ Sensor host ]                              [ Wazuh manager ]
                                            
 zeek writes conn.log  ──┐                  
                         │                  
 staleness script  ──────┤ reads log mtime  
   (cron, every 5 min)   │                  
   writes status line ───┘                  
        │                                   
        ▼                                   
 /var/log/<health>.log ──► Wazuh agent ────► decoder parses status
                            (localfile)       rule: STALE → level 12 alert
                                              rule: OK    → level 0 (silent)
```

The script checks *how old* the newest sensor log is. If older than a
threshold, the sensor has effectively stopped — it emits a `STALE` line.
Otherwise `OK`. The Wazuh agent ships those lines to the manager, where a
custom decoder and rules turn `STALE` into a high-severity alert.

---

## 3. Components

### 3.1 The staleness-check script

Runs on the **sensor host** (the machine running Zeek). Checks the age of the
sensor's live log and writes a single status line to a health log the Wazuh
agent watches.

```bash
#!/bin/bash
# zeek-staleness-check.sh
# Emits a health status line based on how recently the sensor wrote logs.
# Intended to run on a schedule (e.g. every 5 minutes via cron).

LOGFILE="/var/log/zeek-health.log"
CONN_LOG="/opt/zeek/spool/zeek/conn.log"   # adjust to your sensor's live log
THRESHOLD_SECONDS=600                        # 10 min; tune to your traffic

if [ ! -f "$CONN_LOG" ]; then
    echo "ZEEK_HEALTH STALE reason=conn_log_missing" >> "$LOGFILE"
    exit 0
fi

LAST_MOD=$(stat -c %Y "$CONN_LOG")
NOW=$(date +%s)
AGE=$(( NOW - LAST_MOD ))

if [ "$AGE" -gt "$THRESHOLD_SECONDS" ]; then
    echo "ZEEK_HEALTH STALE reason=no_writes age_seconds=$AGE" >> "$LOGFILE"
else
    echo "ZEEK_HEALTH OK age_seconds=$AGE" >> "$LOGFILE"
fi
```

**Design notes:**
- The status line deliberately **leads with `ZEEK_HEALTH`**, not a timestamp.
  Wazuh has built-in decoders that greedily claim lines starting with a
  `YYYY-MM-DD HH:MM:SS` pattern, which would shadow your custom decoder.
  Wazuh timestamps every event on arrival anyway, so a script-side timestamp
  is both redundant and harmful here.
- `THRESHOLD_SECONDS` must exceed the longest normal gap between log writes.
  Even a quiet network sees DNS/mDNS/broadcast traffic every few minutes;
  10 minutes is a safe default that avoids false positives on brief lulls.

Install and schedule:

```bash
sudo install -m 0755 zeek-staleness-check.sh /usr/local/bin/
# Run every 5 minutes
( sudo crontab -l 2>/dev/null; \
  echo "*/5 * * * * /usr/local/bin/zeek-staleness-check.sh" ) | sudo crontab -
```

### 3.2 Wazuh agent — watch the health log

On the sensor host, add a `localfile` block to the agent config
(`/var/ossec/etc/ossec.conf`) so the health log is shipped to the manager:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/zeek-health.log</location>
</localfile>
```

Restart the agent and confirm it's reading the file:

```bash
sudo systemctl restart wazuh-agent
sudo grep "zeek-health" /var/ossec/logs/ossec.log | tail -2
# expect: Analyzing file: '/var/log/zeek-health.log'
```

### 3.3 Decoder — on the Wazuh manager

Add to `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="zeek-health">
  <prematch>ZEEK_HEALTH </prematch>
</decoder>

<decoder name="zeek-health-status">
  <parent>zeek-health</parent>
  <prematch>ZEEK_HEALTH </prematch>
  <regex offset="after_prematch">^(\w+)</regex>
  <order>zeek.health_status</order>
</decoder>
```

Extracts the status word (`OK` / `STALE`) into a field `zeek.health_status`.

### 3.4 Rules — on the Wazuh manager

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="zeek_health,">
  <rule id="100200" level="0">
    <decoded_as>zeek-health</decoded_as>
    <description>Zeek health check event</description>
  </rule>

  <rule id="100201" level="0">
    <if_sid>100200</if_sid>
    <field name="zeek.health_status">OK</field>
    <description>Zeek health: OK, logs are fresh</description>
  </rule>

  <rule id="100202" level="12">
    <if_sid>100200</if_sid>
    <field name="zeek.health_status">STALE</field>
    <description>Zeek health: STALE - network sensor has stopped writing logs</description>
    <group>zeek_down,monitoring_failure,</group>
  </rule>
</group>
```

Design: a level-0 grouper catches every health event silently; `OK` stays
silent (no alert fatigue from healthy heartbeats); `STALE` fires at **level
12** — high severity, because a dead sensor is exactly what you must not miss.

---

## 4. Deploy safely

Validate the config **before** restarting — a bad decoder/rule file will stop
the analysis engine:

```bash
# Validate (catches XML/rule errors without downtime)
/var/ossec/bin/wazuh-analysisd -t   # expect: config valid

# Reload cleanly (prefer the service manager over a blunt container restart)
/var/ossec/bin/wazuh-control restart
```

> In a containerized manager, run these inside the manager container.
> `wazuh-analysisd -t` is the equivalent of `visudo -c` for Wazuh rules —
> always validate before applying.

---

## 5. Test end-to-end

**Logic test (instant)** — feed sample lines to `wazuh-logtest`:

```
ZEEK_HEALTH OK age_seconds=5
   → decoder zeek-health, rule 100201 (level 0)

ZEEK_HEALTH STALE reason=no_writes age_seconds=1800
   → decoder zeek-health, rule 100202 (level 12), "Alert to be generated"
```

**Live test (the real proof)** — temporarily lower the threshold, stop the
sensor, confirm the alert, then restore:

```bash
# On the sensor host
sudo sed -i 's/THRESHOLD_SECONDS=600/THRESHOLD_SECONDS=30/' \
  /usr/local/bin/zeek-staleness-check.sh
sudo /opt/zeek/bin/zeekctl stop
sleep 35
sudo /usr/local/bin/zeek-staleness-check.sh
tail -2 /var/log/zeek-health.log        # expect STALE

# On the manager — confirm the alert fired (match the description text)
grep "network sensor has stopped" /var/ossec/logs/alerts/alerts.log | tail -2
# expect: Rule: 100202 (level 12) -> 'Zeek health: STALE ...'

# Restore
sudo /opt/zeek/bin/zeekctl deploy
sudo sed -i 's/THRESHOLD_SECONDS=30/THRESHOLD_SECONDS=600/' \
  /usr/local/bin/zeek-staleness-check.sh
sudo /usr/local/bin/zeek-staleness-check.sh
tail -2 /var/log/zeek-health.log        # expect OK
```

---

## 6. The three-layer pattern

This alert is the third layer of a resilience pattern worth applying to any
critical control:

```
1. REVIVE     — bring it back when it's down (manual/scripted restart)
2. AUTO-HEAL  — a watchdog restarts it automatically if it crashes
                (e.g. `*/5 * * * * zeekctl cron`)
3. ALERT      — notify when it fails, so a failure of layers 1–2 still
                surfaces (this staleness detection)
```

Run it, make it restart itself, and make it scream when even that fails.
Auto-heal keeps the sensor up; the alert guarantees you *find out* on the
rare occasion auto-heal doesn't.

---

## 7. Lessons learned (Wazuh specifics)

- **Verify the effective config, not the file.** `wazuh-analysisd -t` and
  `wazuh-logtest` show what's actually loaded; a file existing doesn't mean
  its settings are active.
- **Built-in decoders can shadow custom ones.** Lines that start with a
  generic timestamp get claimed by built-in date decoders first. Lead your
  log lines with a distinctive token.
- **Rules are evaluated by level, not file order.** Make sibling rules
  mutually exclusive rather than relying on ordering.
- **Prefer heredocs over `sed` for XML edits.** Multi-layer shell escaping
  around XML is error-prone; write whole blocks with `cat <<'EOF'`.
- **Validate before restart.** `wazuh-analysisd -t` before
  `wazuh-control restart` prevents taking the analysis engine down on a typo.

---

## 8. Adapting this to other controls

The pattern generalizes. Anything that should continuously produce output can
be monitored the same way — swap the log path and the status token:

- A different IDS/sensor's live log
- A backup job's completion marker
- A scheduled scan's result file
- Any service whose "I'm alive" evidence is a file that should keep changing

The check is always the same shape: *how old is the freshest evidence, and is
that older than it should ever be?*

---

*Built and tested in a homelab Wazuh deployment. Paths and thresholds are
examples — adjust to your environment. Nothing in this document is
environment-specific or sensitive.*
