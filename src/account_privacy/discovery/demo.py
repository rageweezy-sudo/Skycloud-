import json
from importlib.resources import files

from account_privacy.core.models import Account, Provider

from .evidence import MailHeader
from .scan import Approval, HeaderPage

ACCOUNT = Account("demo", "demo@example.test", Provider.LOCAL)
SELECTION = "built-in-demo-v1"


class DemoHeaders:
    def page(self, cursor: str | None, approval: Approval) -> HeaderPage:
        resource = files("account_privacy").joinpath("resources", "mock_headers.json")
        data = json.loads(resource.read_text(encoding="utf-8"))
        return HeaderPage(tuple(MailHeader(**item) for item in data["messages"]), None, len(data["messages"]), True)
