"""Design inventory only. Deferred connectors are never registered for scheduled polling."""
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class PlannedSource:
    id: str
    upstream: str
    tier: Literal["free", "paid"] = "free"


PLANNED = (
    PlannedSource("palo_alto", "https://security.paloaltonetworks.com/json"),
    PlannedSource("juniper", "https://supportportal.juniper.net/knowledgerss?type=Security"),
    PlannedSource("hpe_aruba", "https://csaf.arubanetworking.hpe.com"),
    PlannedSource("zscaler", "https://trust.zscaler.com/rss-feed/advisories"),
    PlannedSource("cert_bund", "https://wid.cert-bund.de/portal/wid/kurzinformationen"),
    PlannedSource("ncsc_nl", "https://advisories.ncsc.nl/"),
    PlannedSource("osv", "https://osv.dev/"),
    PlannedSource("ghsa", "https://github.com/advisories"),
    PlannedSource("vulners", "https://vulners.com/", "paid"),
    PlannedSource("notcve", "https://notcve.org/", "paid"),
)
