#!/bin/bash
# zeek-staleness-check.sh
#
# Emits a health status line based on how recently the Zeek sensor wrote logs.
# Intended to run on a schedule (e.g. every 5 minutes via cron) on the sensor
# host. A Wazuh agent watches the output log; a manager-side rule turns a
# STALE status into a high-severity alert.
#
# See docs/monitor-the-monitor.md for the full write-up.

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
