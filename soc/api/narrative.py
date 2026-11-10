"""Plain-English wording for the web UI: one-sentence incident headlines, readable ML reasons and
feature labels. Purely deterministic templates over data the pipeline already produced – no LLM,
nothing is invented."""
import re

# ML feature / reason code → what it means for an analyst
FEATURE_TEXT = {
    # LANL – authentication behaviour
    "n_events": "sign-in events",
    "n_dst_comp": "hosts signed in to",
    "n_src_comp": "hosts signed in from",
    "n_dst_user": "different target accounts used",
    "n_new_dst_comp": "hosts signed in to for the first time",
    "new_dst_ratio": "share of target hosts that are new",
    "n_new_src_comp": "hosts signed in from for the first time",
    "n_new_src_events": "sign-ins from hosts new to this account",
    "new_src_ntlm_events": "NTLM sign-ins from hosts new to this account",
    "new_src_max_fanin": "accounts sharing a newly used source host",
    "src_max_fanin": "accounts sharing a source host",
    "n_new_edge": "network paths nobody used before",
    "n_new_edge_src_new": "never-seen paths from a new source host",
    "fail_ratio": "share of failed sign-ins",
    "ntlm_ratio": "share of NTLM sign-ins",
    "remote_ratio": "share of remote sign-ins",
    "unusual_hour_ratio": "activity at unusual hours",
    "max_per_minute": "peak sign-ins per minute",
    "rare_src_max": "rarest source host for this account",
    "rare_dst_max": "rarest destination host for this account",
    "rare_edge_max": "rarest source → destination path",
    "rare_combo_max": "rarest account + host combination",
    # CERT – employee activity
    "logon_offhours": "logons outside working hours",
    "logon_weekend": "weekend logons",
    "logon_pcs": "PCs logged on to",
    "usb_n": "USB connections",
    "usb_offhours": "after-hours USB connections",
    "file_n": "files copied to USB",
    "file_exe": "executables copied to USB",
    "file_zip": "archives copied to USB",
    "email_ext_rcpt": "external email recipients",
    "email_attach": "email attachments",
    "http_job": "job-search site visits",
    "http_competitor": "competitor site visits",
    "http_rare_max": "rarest website visited",
    "http_n_rare": "very rare websites visited",
    "http_n_new_domain": "websites never visited before",
}


def reason_text(code: str) -> str:
    """'trend_usb_offhours' → 'after-hours USB connections – rising vs the previous 2 months'."""
    m = re.match(r"(trend_|w30_)?(.*)", code)
    prefix, base = m.group(1), m.group(2)
    text = FEATURE_TEXT.get(base, base.replace("_", " "))
    if prefix == "trend_":
        return f"{text} – rising compared with the previous two months"
    if prefix == "w30_":
        return f"{text} – unusually high over the last 30 days"
    return f"unusual {text}"


def label(code: str) -> str:
    return FEATURE_TEXT.get(code, code.replace("_", " "))


def headline(inc: dict) -> str:
    """One sentence that says what happened, built from the attack chain / timeline."""
    c = inc.get("attack_chain") or {}
    ent = inc["entity"].removeprefix("host:")
    if inc["dataset"] == "lanl":
        acc, tgt = len(c.get("compromised_accounts", [])), len(c.get("touched_hosts", []))
        ntlm = [e for e in c.get("timeline", []) if e.get("auth") == "NTLM"]
        how = " mostly over NTLM, a typical Pass-the-Hash sign" if c.get("timeline") and \
            len(ntlm) * 2 >= len(c["timeline"]) else ""
        if inc["entity_type"] == "host":
            if acc >= 3:
                return (f"Host {ent} looks like an attacker's jump host: {acc} accounts signed in "
                        f"from it for the first time and reached {tgt} other hosts{how}.")
            return f"Host {ent} was used by {acc} account(s) that had never used it before."
        main = c.get("main_host")
        if main and acc >= 3:
            return (f"Account {ent} signed in from unfamiliar hosts; the trail leads to {main}, "
                    f"a likely jump host used by {acc} accounts to reach {tgt} hosts{how}.")
        return (f"Account {ent} behaved unlike its usual self "
                f"({inc['n_alerts']} detections from rules and machine learning).")
    phases = c.get("phases") or []
    new = [s for s in c.get("steps", []) if s.get("new")]
    if new:
        firsts = []
        for s in new:
            if s["name"] not in firsts:
                firsts.append(s["name"])
        story = " → ".join(x[0].lower() + x[1:] for x in firsts[:4])
        end = " ending in data theft" if "Exfiltration" in phases else ""
        return f"Employee {ent} started doing new things{end}: {story}."
    return (f"Employee {ent} behaved unlike their usual self "
            f"({inc['n_alerts']} detections from rules and machine learning).")


def fmt_minutes(m) -> str:
    """12.5 → '13 min', 190 → '3.2 h', None → '—'."""
    if m is None:
        return "—"
    if m < 60:
        return f"{m:.0f} min"
    if m < 48 * 60:
        return f"{m / 60:.1f} h"
    return f"{m / 1440:.1f} days"


def phase_color(phase: str) -> str:
    return {"Access": "p1", "Preparation": "p2", "Installation": "p3", "Exfiltration": "p4"}.get(phase, "p1")
