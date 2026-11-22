import json

import pytest

from percy.activity.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "percy.db")
    yield s
    s.close()


class FakeActItem:
    GL, GO, SET = "gl", "go", "so"
    ADD = "ao"

    def __init__(self, type, oid, stack="0,0,0,0,0,0", pstack="0,0,0,0,0,0", attrs=()):
        self.type, self.oid, self.stack, self.pstack, self.attrs = type, oid, stack, pstack, list(attrs)


class FakeLibClient:
    """Stands in for tplinkrouterc6u's EX client: no network, objects held in a dict."""

    ActItem = FakeActItem

    def __init__(self, objects=None, fail_login=None):
        self.objects = objects or {}
        self.fail_login = fail_login
        self.calls = []
        self.logged_out = False

    def authorize(self):
        if self.fail_login:
            raise Exception(self.fail_login)

    def logout(self):
        self.logged_out = True

    def req_act(self, acts):
        out = []
        for act in acts:
            self.calls.append((act.type, act.oid, act.stack, list(act.attrs)))
            if act.type == FakeActItem.ADD:
                row = {"stack": f"{len(self.objects.get(act.oid, [])) + 1},0,0,0,0,0"}
                for attr in act.attrs:
                    row.update(json.loads("{" + attr + "}"))
                self.objects.setdefault(act.oid, []).append(row)
                out.append(None)
                continue
            if act.type == FakeActItem.SET:
                rows = self.objects.setdefault(act.oid, [{"stack": act.stack}])
                row = next((r for r in rows if r.get("stack") == act.stack), rows[0])
                for attr in act.attrs:
                    row.update(json.loads("{" + attr + "}"))
                out.append(None)
            else:
                out.append(self.objects.get(act.oid))
        return "", out
