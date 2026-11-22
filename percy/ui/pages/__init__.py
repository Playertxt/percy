from percy.ui.pages.activity import ActivityPage
from percy.ui.pages.adblock import AdblockPage
from percy.ui.pages.agents import AgentsPage
from percy.ui.pages.devices import DevicesPage
from percy.ui.pages.overview import OverviewPage
from percy.ui.pages.security import SecurityPage
from percy.ui.pages.settings import SettingsPage
from percy.ui.pages.wifi import WifiPage

# (key, class) in sidebar order
PAGES = (
    ("overview", OverviewPage),
    ("devices", DevicesPage),
    ("wifi", WifiPage),
    ("adblock", AdblockPage),
    ("security", SecurityPage),
    ("activity", ActivityPage),
    ("agents", AgentsPage),
    ("settings", SettingsPage),
)
