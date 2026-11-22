"""Map a looked-up domain to the app or service it belongs to.

HTTPS hides the full link, so the domain is the finest detail a home network can
see. Suffix rules: 'ytimg.com' also matches 'i.ytimg.com'.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AppMatch:
    app: str
    category: str


# (app, category, domain suffixes)
_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("YouTube", "Video", ("youtube.com", "ytimg.com", "googlevideo.com", "youtu.be", "youtubei.googleapis.com")),
    ("Netflix", "Video", ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com")),
    ("Prime Video", "Video", ("primevideo.com", "aiv-cdn.net", "aiv-delivery.net")),
    ("JioHotstar", "Video", ("hotstar.com", "jiohotstar.com", "hotstarext.com", "jiocinema.com")),
    ("Twitch", "Video", ("twitch.tv", "ttvnw.net", "jtvnw.net")),
    ("Instagram", "Social", ("instagram.com", "cdninstagram.com", "ig.me")),
    ("Facebook", "Social", ("facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com")),
    ("WhatsApp", "Messaging", ("whatsapp.com", "whatsapp.net", "wa.me")),
    ("Telegram", "Messaging", ("telegram.org", "t.me", "telegram.me", "tdesktop.com")),
    ("Snapchat", "Social", ("snapchat.com", "sc-cdn.net", "snap-dev.net", "snapkit.com")),
    ("TikTok", "Social", ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com")),
    ("X (Twitter)", "Social", ("twitter.com", "x.com", "twimg.com", "t.co")),
    ("Reddit", "Social", ("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com")),
    ("Discord", "Messaging", ("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media")),
    ("Spotify", "Music", ("spotify.com", "scdn.co", "spotifycdn.com", "spotify.design")),
    ("JioSaavn", "Music", ("jiosaavn.com", "saavn.com", "saavncdn.com")),
    ("Steam", "Games", ("steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com")),
    ("Epic Games", "Games", ("epicgames.com", "epicgames.dev", "unrealengine.com", "fortnite.com")),
    ("BGMI / PUBG", "Games", ("battlegroundsmobileindia.com", "pubgmobile.com", "igamecj.com", "proximabeta.com")),
    ("Free Fire", "Games", ("ff.garena.com", "garena.com", "freefiremobile.com")),
    ("Roblox", "Games", ("roblox.com", "rbxcdn.com", "rbx.com")),
    ("Minecraft", "Games", ("minecraft.net", "mojang.com", "minecraftservices.com")),
    ("PlayStation", "Games", ("playstation.com", "playstation.net", "sonyentertainmentnetwork.com")),
    ("Xbox", "Games", ("xbox.com", "xboxlive.com", "xboxservices.com")),
    ("ChatGPT", "AI", ("chatgpt.com", "openai.com", "oaiusercontent.com")),
    ("Claude", "AI", ("claude.ai", "anthropic.com")),
    ("Gemini", "AI", ("gemini.google.com",)),
    ("Gmail", "Email", ("mail.google.com", "gmail.com")),
    ("Google Search", "Search", ("google.com", "google.co.in", "gstatic.com", "googleapis.com")),
    ("Bing", "Search", ("bing.com",)),
    ("Amazon", "Shopping", ("amazon.in", "amazon.com", "media-amazon.com", "ssl-images-amazon.com")),
    ("Flipkart", "Shopping", ("flipkart.com", "flixcart.com", "flipkart.net")),
    ("Myntra", "Shopping", ("myntra.com", "myntassets.com")),
    ("Paytm", "Payments", ("paytm.com", "paytm.in", "paytmbank.com")),
    ("PhonePe", "Payments", ("phonepe.com",)),
    ("Google Pay", "Payments", ("pay.google.com",)),
    ("Zoom", "Calls", ("zoom.us", "zoom.com", "zoomgov.com")),
    ("Microsoft Teams", "Calls", ("teams.microsoft.com", "teams.live.com", "skype.com")),
    ("Microsoft", "System", ("microsoft.com", "windowsupdate.com", "live.com", "office.com", "msftconnecttest.com")),
    ("Apple", "System", ("apple.com", "icloud.com", "mzstatic.com", "apple-dns.net")),
    ("Android / Google services", "System", ("android.com", "googleusercontent.com", "gvt1.com", "gvt2.com", "1e100.net")),
    ("Xiaomi", "System", ("xiaomi.com", "mi.com", "miui.com", "xiaomi.net")),
    ("Samsung", "System", ("samsung.com", "samsungcloud.com", "samsungapps.com", "samsungqbe.com")),
    ("Wikipedia", "Reading", ("wikipedia.org", "wikimedia.org")),
    ("GitHub", "Work", ("github.com", "githubusercontent.com", "githubassets.com")),
    ("Cloudflare", "Infrastructure", ("cloudflare.com", "cloudflare-dns.com", "one.one.one.one")),
    ("Akamai CDN", "Infrastructure", ("akamaihd.net", "akamaized.net", "akamai.net", "akadns.net")),
    ("Ads & tracking", "Ads", ("doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com",
                               "app-measurement.com", "appsflyer.com", "adjust.com", "branch.io", "scorecardresearch.com",
                               "criteo.com", "taboola.com", "outbrain.com", "mopub.com", "unityads.unity3d.com")),
)

_INDEX: dict[str, AppMatch] = {
    suffix: AppMatch(app, category) for app, category, suffixes in _RULES for suffix in suffixes
}


def classify(domain: str) -> AppMatch | None:
    """Longest matching suffix wins, so 'mail.google.com' is Gmail, not Google Search."""
    labels = domain.strip().rstrip(".").lower().split(".")
    for start in range(len(labels) - 1):
        match = _INDEX.get(".".join(labels[start:]))
        if match:
            return match
    return None


def site_of(domain: str) -> str:
    """Rough 'site' name for unknown domains: last two labels (three for co.in-style)."""
    labels = domain.strip().rstrip(".").lower().split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
