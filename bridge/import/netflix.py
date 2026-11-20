"""Netflix viewing history, from your own downloads (see history_import.py). Two files exist:

1. Per profile, "Viewing activity" page, "Download all": NetflixViewingHistory.csv with two
   columns, Title and Date. Title is "Show: Season 1: Episode name" or a film's name. No profile
   in the file, so the person comes from the file or folder name.
2. Whole account, "Download your personal information" (a zip, takes Netflix a day or two):
   CONTENT_INTERACTION/ViewingActivity.csv with Profile Name, Start Time (UTC), Duration, Title,
   Supplemental Video Type (trailers and previews, skipped), Bookmark and more. Better data:
   how long each sitting lasted, so finished and abandoned can be told apart.
"""
import csv
import hashlib
import io
import re
from datetime import datetime, timezone

SEASON_RE = re.compile(
    r"^(?P<show>.+?): (?P<season>(?:Season|Series|Part|Volume|Chapter|Book) \d+|Limited Series|"
    r"Miniseries|Collection \d+)(?:: (?P<episode>.+))?$")
EPISODE_NO_RE = re.compile(r"\s*\(Episode (\d+)\)\s*$")


def split_title(title):
    """'Stranger Things: Season 2: Chapter Three (Episode 3)' -> show, season, episode name, no."""
    title = (title or "").strip()
    m = SEASON_RE.match(title)
    if not m:
        return {"series": None, "season_label": None, "season": None, "episode_title": None,
                "episode": None, "kind": "film_or_special", "title": title}
    ep_title = m.group("episode")
    ep_no = None
    if ep_title:
        n = EPISODE_NO_RE.search(ep_title)
        if n:
            ep_no = int(n.group(1))
            ep_title = EPISODE_NO_RE.sub("", ep_title)
    season_label = m.group("season")
    sn = re.search(r"\d+", season_label)
    return {"series": m.group("show"), "season_label": season_label,
            "season": int(sn.group()) if sn and season_label.split()[0] in ("Season", "Series") else None,
            "episode_title": ep_title, "episode": ep_no, "kind": "episode", "title": m.group("show")}


SLASH_DATE_RE = re.compile(r"\s*(\d{1,2})/(\d{1,2})/\d{2,4}\s*$")


def _month_first(dates):
    """Netflix writes the date in the account's locale: day first in Australia ("30/7/13"), month
    first in the US ("7/30/13"). Decide once for the whole file, from the rows only one order can
    read: reading row by row turned a US "4/12/26" (12 April) into 4 December."""
    day_first = month_first = 0
    for text in dates:
        m = SLASH_DATE_RE.match(text or "")
        if m:
            day_first += int(m.group(1)) > 12
            month_first += int(m.group(2)) > 12
    return month_first > day_first


def _date(text, month_first=False):
    text = (text or "").strip()
    slash = ("%m/%d/%Y", "%m/%d/%y") if month_first else ("%d/%m/%Y", "%d/%m/%y")
    for fmt in (*slash, "%Y-%m-%d", "%d.%m.%y", "%d.%m.%Y"):
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _seconds(hms):
    try:
        h, m, s = (int(x) for x in (hms or "").split(":"))
        return h * 3600 + m * 60 + s
    except ValueError:
        return None


def _key(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def looks_like(header):
    cols = [c.strip().lower() for c in header]
    if "profile name" in cols and "start time" in cols and "title" in cols:
        return "full"
    if cols[:2] == ["title", "date"]:
        return "profile"
    return None


def parse(text, person_for):
    """Rows -> history items. person_for(profile_name_or_None) gives a person id / None."""
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    kind = looks_like(rows[0])
    if not kind:
        return []
    header = [c.strip() for c in rows[0]]
    month_first = kind == "profile" and _month_first(dict(zip(header, raw)).get("Date") for raw in rows[1:])
    out = []
    for raw in rows[1:]:
        if not raw or not any(raw):
            continue
        r = dict(zip(header, raw))
        if kind == "profile":
            when = _date(r.get("Date"), month_first)
            if not when:
                continue
            t = split_title(r.get("Title"))
            out.append({
                "key": _key("netflix", "profile", person_for(None), r.get("Title"), when),
                "source": "netflix", "who": person_for(None), "profile": None, "when": when,
                "duration_s": None, **t, "raw_title": r.get("Title")})
        else:
            if (r.get("Supplemental Video Type") or "").strip():
                continue  # trailers, previews, hooks
            try:
                when = datetime.strptime(r["Start Time"].strip(), "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc).isoformat()
            except (KeyError, ValueError):
                continue
            t = split_title(r.get("Title"))
            profile = (r.get("Profile Name") or "").strip()
            out.append({
                "key": _key("netflix", "full", profile, r.get("Title"), when),
                "source": "netflix", "who": person_for(profile), "profile": profile, "when": when,
                "duration_s": _seconds(r.get("Duration")), "device": r.get("Device Type"), **t,
                "raw_title": r.get("Title")})
    return out
