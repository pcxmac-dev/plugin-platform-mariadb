"""What the MariaDB plugin attaches to (plugin API 2.2): its card is sound, every address one of MariaDB's own pages
or PyMySQL's; it names the statements the plugin itself sends; what it knows of MariaDB here asks no server and loads no
driver; and the card's pages answer (LIMINAL_VENDOR_PAGES=1 only, the one test that reaches the network: the addresses
were written from what was known of the sites, not fetched)."""
from __future__ import annotations

import inspect
import os
import sys

import pytest

import plugin_platform_mariadb as module
from liminal_libs.sources.apis import dead_links, problems, urls
from plugin_platform_mariadb import DATABASE
from plugin_platform_mariadb import apis as cards


def test_the_card_is_sound_and_links_the_makers_own_pages():
    assert problems(DATABASE.apis) == [] and DATABASE.apis == cards.APIS == (cards.MARIADB,)
    api = cards.MARIADB
    assert (api.name, api.kind, api.verified, api.costs) == ("MariaDB", "sdk", "2026-11-25", "") and api.docs == cards.DOCS
    assert all(u.startswith(("https://mariadb.com/kb/en/", "https://pymysql.readthedocs.io/", "https://github.com/PyMySQL/",
                             "https://pypi.org/project/PyMySQL/")) for u in urls(DATABASE.apis))
    assert {x.kind for x in api.links} == {"docs", "reference", "sdk", "guide", "changelog", "terms"}
    assert len(api.areas) > len(api.covered) >= 6 and len(api.calls) > len(api.used) >= 10
    assert {c.area for c in api.calls} <= {a.name for a in api.areas}
    assert "over TLS alone" in next(a.covered for a in api.areas if a.name == "TLS")
    assert {c.name for c in api.calls if c.writes} >= {"CREATE USER ... IDENTIFIED BY", "DROP USER IF EXISTS",
                                                        "CREATE DATABASE ... CHARACTER SET utf8mb4", "DROP DATABASE IF EXISTS"}


def test_the_card_names_what_the_plugin_itself_sends():
    src = inspect.getsource(module)
    used = " ".join(c.name for c in cards.MARIADB.used)
    for sent, named in (("SELECT VERSION()", "SELECT VERSION()"), ("information_schema.tables", "information_schema.TABLES"),
                        ("information_schema.schemata", "information_schema.SCHEMATA"), ("FROM mysql.user", "mysql.user"),
                        ("USER {account} IDENTIFIED BY", "CREATE USER ... IDENTIFIED BY"),
                        ('"ALTER" if there', "ALTER USER ... IDENTIFIED BY"), ("DROP USER IF EXISTS", "DROP USER IF EXISTS"),
                        ("GRANT ALL PRIVILEGES ON {identifier(name)}.* TO", "GRANT ALL PRIVILEGES ON db.* TO"),
                        ("CREATE DATABASE {identifier(name)} CHARACTER SET", "CREATE DATABASE ... CHARACTER SET utf8mb4"),
                        ("DROP DATABASE IF EXISTS", "DROP DATABASE IF EXISTS"),
                        ("CREATE TABLE IF NOT EXISTS {MARKER}", "CREATE TABLE liminal_instance, INSERT"),
                        ("SET SESSION TRANSACTION READ ONLY", "SET SESSION TRANSACTION READ ONLY")):
        assert sent in src and named in used
    for never in ("mysqld_safe", "mariadbd --", "mysqladmin", "subprocess", "DROP DATABASE {", "WITH GRANT OPTION", "SHUTDOWN"):
        assert never not in src  # it starts and ends no server, drops only what it just made, and grants no granting
    assert module.PORT == 3306 and module.GRANTS == ("ALL PRIVILEGES",)


def test_what_it_knows_of_mariadb_here_asks_no_server_and_loads_no_driver(monkeypatch):
    was = {name: sys.modules.pop(name) for name in list(sys.modules) if name == "pymysql" or name.startswith("pymysql.")}
    monkeypatch.setattr(module, "my_connect", lambda **k: pytest.fail("a server was asked"))
    try:
        facts = module.MariadbPlugin().api_facts()
        assert list(facts) == ["MariaDB"] and facts["MariaDB"]["Its own server"].startswith("none")
        assert facts["MariaDB"]["Methods here"].startswith("tcp and a Unix socket" if module.SOCKETS else "tcp alone")
        assert "pymysql" not in sys.modules
    finally:
        sys.modules.update(was)


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_the_cards_pages_answer():
    assert dead_links(DATABASE.apis) == []
