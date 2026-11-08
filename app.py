import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Playfair+Display:wght@500;600;700&display=swap');
.stApp{background:#0b111b;color:#f3f1eb}
[data-testid="stSidebar"]{background:#101925}
h1,h2,h3{font-family:'Playfair Display',Georgia,serif!important}
div[data-testid="stMetric"]{background:#121d2b;border:1px solid #574a32;padding:14px;border-radius:10px}
div.stButton>button,div.stDownloadButton>button{background:#c9a96a;color:#101722;border:0;font-weight:700}
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ CyberShield")
st.sidebar.caption("INTELLIGENT INTEGRATED CYBER DEFENSE SYSTEM")
page = st.sidebar.radio("Navigation", ["Overview", "Event Analysis", "Risk Report", "About"])
st.sidebar.divider()
st.sidebar.caption("Defensive security analytics · MVP")

sample = pd.DataFrame([
 ["2026-11-08 09:00:00","192.168.1.10","login_success",0,1200,443],
 ["2026-11-08 09:02:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:03:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:04:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:05:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:10:00","192.168.1.22","data_transfer",0,8500000,443],
 ["2026-11-08 09:12:00","192.168.1.30","port_connection",0,800,3389],
 ["2026-11-08 09:15:00","192.168.1.10","login_success",0,1000,443],
 ["2026-11-08 09:17:00","192.168.1.42","dns_request",0,300,53],
], columns=["timestamp","source_ip","event_type","failed_logins","bytes_out","destination_port"])

def analyse(frame):
    df = frame.copy()
    required = ["timestamp","source_ip","event_type"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    for c in ["failed_logins","bytes_out","destination_port"]:
        if c not in df: df[c] = 0
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str)
    df["event_type"] = df["event_type"].fillna("unknown").astype(str).str.lower()
    scores, reasons = [], []
    for _, r in df.iterrows():
        score, why = 0, []
        if r.failed_logins >= 5: score += 55; why.append("5+ failed logins recorded")
        elif r.failed_logins >= 3: score += 35; why.append("3–4 failed logins recorded")
        if r.bytes_out >= 5_000_000: score += 35; why.append("Outbound data volume is at least 5 MB")
        elif r.bytes_out >= 1_000_000: score += 20; why.append("Outbound data volume is at least 1 MB")
        if r.destination_port in [23,3389,4444]: score += 20; why.append(f"Review destination port {int(r.destination_port)}")
        if "failed" in r.event_type: score += 10; why.append("Event type indicates a failed action")
        scores.append(min(score,100))
        reasons.append("; ".join(why) if why else "No configured rule triggered")
    df["risk_score"] = scores
    df["risk_level"] = ["High" if x >= 60 else "Medium" if x >= 30 else "Low" for x in scores]
    df["reason"] = reasons
    return df

if "results" not in st.session_state: st.session_state.results = analyse(sample)
st.title("CyberShield")
st.caption("Intelligent Integrated Cyber Defense System · Security Event Monitoring & Risk Assessment")
st.sidebar.markdown("### Data input")
choice = st.sidebar.radio("Dataset", ["Built-in sample", "Upload CSV"])
upload = st.sidebar.file_uploader("Upload event log CSV", type=["csv"]) if choice == "Upload CSV" else None
st.sidebar.caption("Required: timestamp, source_ip, event_type. Optional: failed_logins, bytes_out, destination_port.")
if st.sidebar.button("Analyse events", use_container_width=True):
    try:
        if choice == "Upload CSV":
            if upload is None: st.sidebar.warning("Choose a CSV file first.")
            else:
                st.session_state.results = analyse(pd.read_csv(upload))
                st.sidebar.success("Analysis completed.")
        else:
            st.session_state.results = analyse(sample)
            st.sidebar.success("Sample analysed.")
    except Exception as e: st.sidebar.error(str(e))

df = st.session_state.results
counts = df.risk_level.value_counts()
high, medium, low = [int(counts.get(x,0)) for x in ["High","Medium","Low"]]

if page == "Overview":
    st.subheader("Security posture at a glance")
    a,b,c,d = st.columns(4)
    a.metric("Events analysed",len(df)); b.metric("High risk",high); c.metric("Medium risk",medium); d.metric("Low risk",low)
    left,right = st.columns([1,1.5])
    with left:
        st.markdown("#### Risk distribution")
        st.bar_chart(pd.DataFrame({"Events":[high,medium,low]},index=["High","Medium","Low"]))
    with right:
        st.markdown("#### Recent events")
        st.dataframe(df[["timestamp","source_ip","event_type","risk_level","risk_score"]].tail(8),use_container_width=True,hide_index=True)
    st.info("Risk labels prioritise events for human review. They are not proof that an attack occurred.")
elif page == "Event Analysis":
    st.subheader("Event analysis")
    levels = st.multiselect("Risk levels",["High","Medium","Low"],default=["High","Medium","Low"])
    filtered = df[df.risk_level.isin(levels)]
    st.dataframe(filtered,use_container_width=True,hide_index=True)
    if not filtered.empty:
        ip = st.selectbox("Inspect source",filtered.source_ip.unique())
        for _,r in filtered[filtered.source_ip==ip].iterrows():
            st.markdown(f"**{r.risk_level} · {r.risk_score}/100 · {r.event_type}**")
            st.write(r.reason)
elif page == "Risk Report":
    st.subheader("Risk assessment report")
    st.write("Generated:",datetime.now().strftime("%Y-%m-%d %H:%M"))
    st.write(f"Reviewed: **{len(df)}** · High: **{high}** · Medium: **{medium}** · Low: **{low}**")
    high_rows = df[df.risk_level=="High"]
    if high_rows.empty: st.success("No High-risk events were flagged by the current rules.")
    else:
        st.warning("High-risk events need analyst review.")
        st.dataframe(high_rows[["timestamp","source_ip","event_type","risk_score","reason"]],use_container_width=True,hide_index=True)
    st.download_button("Download analysed report",df.to_csv(index=False).encode(), "cybershield_report.csv","text/csv")
else:
    st.subheader("About this prototype")
    st.markdown("""
**CyberShield — Intelligent Integrated Cyber Defense System**

This first version demonstrates a defensive workflow:
1. Load security event records from a sample dataset or CSV.
2. Apply transparent rules to identify events that may need attention.
3. Assign Low, Medium, or High risk levels with an explainable score.
4. Review findings and export a report.

**Current scope:** analyses supplied log records only. It does not scan networks, intercept traffic, block devices, or perform automated response actions. Rules are illustrative and need validation against representative data. A flagged event is not necessarily malicious.

**Roadmap:** improved log normalisation, time-window correlation, behaviour baselines, evaluated machine-learning models, and analyst feedback.
""")
st.divider()
st.caption("CYBERSHIELD · DEFENSIVE SECURITY ANALYTICS · EDUCATIONAL PROTOTYPE")
