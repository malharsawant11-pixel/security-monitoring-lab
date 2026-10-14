
import csv
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Security Monitoring Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Security Monitoring Dashboard")
st.caption("Authentication Log Analysis and Incident Investigation")

REPORT_FILE = Path("reports/alerts.csv")

if not REPORT_FILE.exists():
    st.warning("No alert report found. Run the log analyzer first.")
    st.code("python src/log_analyzer.py")
    st.stop()

try:
    with REPORT_FILE.open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    df = pd.DataFrame(rows)

except (OSError, csv.Error, UnicodeError) as error:
    st.error(f"Could not read the alert report: {error}")
    st.stop()

if df.empty:
    st.info("No alerts are currently recorded in the report.")
    st.stop()

for column in [
    "source_ip",
    "failed_attempts",
    "status",
    "rule",
    "timestamp",
    "username",
]:
    if column not in df.columns:
        df[column] = ""

df["failed_attempts"] = pd.to_numeric(
    df["failed_attempts"], errors="coerce"
)

# Assign severity based on the detection rule.
severity_map = {
    "REPEATED_FAILED_LOGINS": "MEDIUM",
    "SUCCESS_AFTER_REPEATED_FAILURES": "HIGH",
    "ACCOUNT_LOCKOUT": "MEDIUM",
}

df["severity"] = (
    df["rule"]
    .map(severity_map)
    .fillna("LOW")
)
total_alerts = len(df)
investigations = int(
    df["status"].eq("INVESTIGATE").sum()
)
unique_sources = int(
    df["source_ip"].replace("", pd.NA).nunique()
)
detection_rules = int(df["rule"].nunique())

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", total_alerts)
col2.metric("Needs Investigation", investigations)
col3.metric("Unique Sources", unique_sources)
col4.metric("Detection Rules", detection_rules)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Alerts by Detection Rule")
    rule_counts = (
        df["rule"]
        .replace("", "Unknown")
        .value_counts()
    )
    st.bar_chart(rule_counts)

with right:
    st.subheader("Alert Status")
    status_counts = (
        df["status"]
        .replace("", "Unknown")
        .value_counts()
    )
    st.bar_chart(status_counts)

st.divider()
st.subheader("Alert Investigation Table")

severity_options = ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

selected_severity = st.selectbox(
    "Filter by severity",
    severity_options,
)

if selected_severity != "All":
    df = df[df["severity"] == selected_severity]

search = st.text_input(
    "Search by source, username, or detection rule"
)

filtered = df.copy()

if search:
    mask = filtered.astype(str).apply(
        lambda column: column.str.contains(
            search, case=False, na=False
        )
    ).any(axis=1)
    filtered = filtered[mask]

st.dataframe(
    filtered,
    use_container_width=True,
    hide_index=True,
)

st.caption(
    "Data source: reports/alerts.csv. "
    "Refresh the dashboard after generating a new report."
)

if st.button("Refresh Dashboard"):
    st.rerun()
