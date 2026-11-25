"""The MariaDB plugin against a stand-in driver (a fake pymysql whose connect answers for stand-in servers: no server
is started, asked or needed; no process, no port, no network): it has no instance of its own and starts no server; a
database on a server is connected only when it answers, signing in as the account given; one off this machine only
when asked twice, over TLS with the certificate checked, and signed in; a socket on Linux alone; a new database gets an
account of its own with every privilege on it alone, the administrator not kept, and a make that fails is taken back
whole; every connection it makes is closed; a sign-in never reaches what is kept or shown; without its driver it says
so."""
from __future__ import annotations

import importlib.machinery
import json
import re
import ssl
import sys
import types
from types import SimpleNamespace

import pytest

import plugin_platform_mariadb as module
from liminal_libs.apps import EnvironmentLogin
from liminal_libs.apps.authorization import Unauthorized
from liminal_libs.storage import databases
from liminal_libs.storage.databases import Refusal
from plugin_platform_mariadb import DATABASE, MARKER, MariadbPlugin, __version__


class OperationalError(Exception):
    """PyMySQL's: the server's code and its message."""


class InterfaceError(Exception):
    """PyMySQL's, for a connection gone."""


def fail(code: int, message: str) -> OperationalError:
    return OperationalError(code, message)


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []

    def _super(self):
        if not self.conn.account().get("super"):
            raise fail(1227, "Access denied; you need (at least one of) the CREATE USER privilege(s) for this operation")

    def execute(self, sql, args=None):
        conn, server = self.conn, self.conn.server
        server["log"].append((conn.user, conn.database, sql))
        db = server["dbs"].get(conn.database) if conn.database else None
        self.rows = []
        if sql == "SELECT VERSION()":
            self.rows = [(server["version"],)]
        elif sql == "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name":
            self.rows = [(t,) for t in sorted(db["tables"])]
        elif sql == "SELECT table_name FROM information_schema.tables WHERE table_schema = %s":
            self.rows = [(t,) for t in sorted(server["dbs"][args[0]]["tables"])]
        elif m := re.fullmatch(rf"SELECT COUNT\(\*\) FROM `([^`]+)`\.{MARKER}", sql):
            self.rows = [(len(server["dbs"][m.group(1)]["tables"][MARKER]),)]
        elif sql == f"SELECT made, holds FROM {MARKER} WHERE id = %s":
            self.rows = [(r["made"], r["holds"]) for r in db["tables"].get(MARKER, []) if r["id"] == args[0]]
        elif sql == "SELECT 1 FROM mysql.user WHERE User = %s AND Host = %s":
            self._super()
            self.rows = [(1,)] if tuple(args) in server["users"] else []
        elif sql == "SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s":
            self.rows = [(args[0],)] if args[0] in server["dbs"] else []
        elif m := re.fullmatch(r"(CREATE|ALTER) USER '([^']+)'@'([^']+)' IDENTIFIED BY '([^']*)'", sql):
            self._super()
            verb, user, host, password = m.groups()
            if verb == "CREATE" and (user, host) in server["users"]:
                raise fail(1396, f"Operation CREATE USER failed for '{user}'@'{host}'")
            if verb == "ALTER" and (user, host) not in server["users"]:
                raise fail(1396, f"Operation ALTER USER failed for '{user}'@'{host}'")
            server["users"][(user, host)] = {"password": password}
            server["made"].append((verb, user, host))
        elif m := re.fullmatch(r"CREATE DATABASE `([^`]+)` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", sql):
            self._super()
            if m.group(1) in server["dbs"]:
                raise fail(1007, f"Can't create database '{m.group(1)}'; database exists")
            server["dbs"][m.group(1)] = {"tables": {}}
        elif m := re.fullmatch(r"GRANT ALL PRIVILEGES ON `([^`]+)`\.\* TO '([^']+)'@'([^']+)'", sql):
            self._super()
            server["grants"].setdefault((m.group(2), m.group(3)), set()).add(m.group(1))
        elif m := re.fullmatch(r"DROP DATABASE IF EXISTS `([^`]+)`", sql):
            if server.get("drop_fails"):
                raise InterfaceError(0, "")
            self._super()
            server["dbs"].pop(m.group(1), None)
            server["dropped"].append(("database", m.group(1)))
        elif m := re.fullmatch(r"DROP USER IF EXISTS '([^']+)'@'([^']+)'", sql):
            if server.get("drop_fails"):
                raise InterfaceError(0, "")
            self._super()
            server["users"].pop((m.group(1), m.group(2)), None)
            server["grants"].pop((m.group(1), m.group(2)), None)
            server["dropped"].append(("user", m.group(1), m.group(2)))
        elif sql.startswith(f"CREATE TABLE IF NOT EXISTS {MARKER} ("):
            if not conn.may(conn.database):
                raise fail(1142, f"CREATE command denied to user '{conn.user}'")
            db["tables"].setdefault(MARKER, [])
        elif sql.startswith(f"INSERT INTO {MARKER} (id, name, made, holds, made_by) VALUES"):
            if conn.read_only:
                raise fail(1792, "Cannot execute statement in a READ ONLY transaction")
            if server.get("insert_fails"):
                server["insert_fails"] -= 1
                raise OperationalError(2013, "Lost connection to server during query")
            db["tables"][MARKER].append(dict(zip(("id", "name", "made", "holds", "made_by"), args)))
        elif sql == "SET SESSION TRANSACTION READ ONLY":
            conn.read_only = True
        else:
            raise fail(1064, f"You have an error in your SQL syntax near {sql[:20]!r}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, servers, server, user, host, database, given):
        self.servers, self.server, self.user, self.host, self.database, self.given = (
            servers, server, user, host, database, given)
        self.closed = self.read_only = False
        servers.connections.append(self)

    def account(self) -> dict:
        return self.server["users"][(self.user, self.host)]

    def may(self, database) -> bool:
        return bool(self.account().get("super")) or database in self.server["grants"].get((self.user, self.host), ())

    def cursor(self):
        assert not self.closed, "a closed connection was used"
        return FakeCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def fake_driver(servers) -> types.ModuleType:
    """A stand-in pymysql: connect answers for `servers.at`, by ("tcp", host, port) or ("socket", file); an account
    signs in from 'localhost' over a socket, from '%' over tcp."""

    def connect(user=None, password="", host=None, database=None, unix_socket=None, port=0, charset="", ssl=None,
                connect_timeout=10, read_timeout=None, write_timeout=None, autocommit=False, program_name=None):
        given = dict(user=user, password=password, host=host, database=database, unix_socket=unix_socket, port=port,
                     charset=charset, ssl=ssl, connect_timeout=connect_timeout, read_timeout=read_timeout,
                     write_timeout=write_timeout, autocommit=autocommit, program_name=program_name)
        servers.given.append(given)
        key = ("socket", unix_socket) if unix_socket is not None else ("tcp", host, port)
        server = servers.at.get(key)
        if server is None:
            raise OperationalError(2003, f"Can't connect to MySQL server on '{host}' ([Errno 111] Connection refused)")
        origin = "localhost" if unix_socket is not None else "%"
        account = server["users"].get((user, origin))
        tls_ok = not server.get("tls") or isinstance(ssl, _ssl.SSLContext)
        if account is None or not tls_ok or (account["password"] is not None and account["password"] != password):
            raise fail(1045, f"Access denied for user '{user}'@'{origin}' (using password: {'YES' if password else 'NO'})")
        if database is not None:
            if database not in server["dbs"]:
                raise fail(1049, f"Unknown database '{database}'")
            conn = FakeConnection(servers, server, user, origin, database, given)
            if not conn.may(database):
                conn.close()
                raise fail(1044, f"Access denied for user '{user}'@'{origin}' to database '{database}'")
            return conn
        return FakeConnection(servers, server, user, origin, None, given)

    pkg = types.ModuleType("pymysql")
    pkg.__spec__ = importlib.machinery.ModuleSpec("pymysql", None)
    pkg.connect, pkg.paramstyle = connect, "pyformat"
    pkg.OperationalError, pkg.InterfaceError = OperationalError, InterfaceError
    return pkg


_ssl = ssl


def server(**more) -> dict:
    return {"version": "11.4.3-MariaDB-ubu2404", "users": {("root", "%"): {"password": "admin-secret", "super": True}},
            "dbs": {"mysql": {"tables": {"user": []}}}, "grants": {}, "made": [], "dropped": [], "log": [], **more}


@pytest.fixture
def mys(tmp_path, monkeypatch):
    """The plugin attached to an app whose data folder is the test's, its driver a stand-in; `servers.at` is what
    answers and what listens on this machine; another machine is never asked whether it listens."""
    servers = SimpleNamespace(at={}, connections=[], given=[], fresh=[])
    monkeypatch.setitem(sys.modules, "pymysql", fake_driver(servers))
    monkeypatch.setattr(module, "_os_user", lambda: "ciara")

    def listening(host, port, timeout=0.3, fresh=False):
        assert databases.is_local(host), f"{host} asked whether it listens without the user's test"
        if fresh:
            servers.fresh.append((host, port))
        return ("tcp", host, port) in servers.at

    monkeypatch.setattr(databases, "listening", listening)
    data = tmp_path / "data"
    data.mkdir()
    env: dict = {}
    plugin = MariadbPlugin()
    plugin.attach(SimpleNamespace(db_path=data / "liminal.db"), EnvironmentLogin(env=env))
    yield plugin, servers, env
    assert all(c.closed for c in servers.connections), "a connection was left open"


def test_it_has_no_instance_of_its_own_and_starts_no_server(mys):
    plugin, servers, env = mys
    assert DATABASE.name == "mariadb" and isinstance(DATABASE, MariadbPlugin) and plugin.default_port() == 3306
    assert plugin.instances() == ()
    status = plugin.status()
    assert (status["engine"], status["engineTitle"], status["server"], status["shares"], status["defaultPort"]) == (
        "mariadb", "MariaDB", True, False, 3306)
    assert status["driver"] == {"name": "pymysql", "ok": True, "why": ""} and [h["name"] for h in status["holds"]] == ["documents"]
    assert [m["name"] for m in status["methods"]] == list(plugin.METHODS) and status["instances"] == []
    assert status["can"]["new"] and status["can"]["connect"] and status["can"]["share"] is False
    facts = plugin.api_facts()["MariaDB"]
    assert facts["Its own server"].startswith("none") and facts["PyMySQL in this Python"]
    with pytest.raises(Refusal, match="nothing listens at 127.0.0.1:3306: the plugin starts no server"):
        plugin.connect_to("docs", "127.0.0.1", database="docs")
    assert servers.given == [] and env == {}  # nothing listens: no connection is tried to find that out


def test_without_its_driver_it_says_so_and_everything_else_works(mys, monkeypatch):
    plugin, servers, env = mys
    monkeypatch.setitem(sys.modules, "pymysql", None)  # (find_spec then says there is none, and an import fails)
    status = plugin.status()
    assert status["driver"]["ok"] is False and status["driver"]["why"].startswith("driver not installed: PyMySQL")
    assert status["can"]["new"] is False and status["can"]["why"].startswith("driver not installed")
    with pytest.raises(Refusal, match="driver not installed"):
        plugin.connect_to("docs", "127.0.0.1:3307", database="docs")
    with pytest.raises(Refusal, match="driver not installed"):
        plugin.new_database("docs", "127.0.0.1:3307", admin_user="root", admin_password="admin-secret")
    assert plugin.api_facts()["MariaDB"]["Methods here"] and env == {}


def test_a_database_on_a_server_is_connected_only_when_it_answers_signed_in_as_the_account_given(mys):
    plugin, servers, env = mys
    here = servers.at[("tcp", "127.0.0.1", 3307)] = server()
    here["users"][("reader", "%")] = {"password": "r-secret"}
    here["dbs"]["docs"] = {"tables": {"filings": [], "news": []}}
    here["grants"][("reader", "%")] = {"docs"}
    with pytest.raises(Refusal, match=r"did not answer, so it is not kept: Access denied for user 'ciara'@'%' "
                                      r"\(using password: NO\) \(1045\)"):
        plugin.connect_to("docs", "127.0.0.1:3307", database="docs")
    with pytest.raises(Refusal, match="did not answer, so it is not kept: Access denied for user 'reader'"):
        plugin.connect_to("docs", "127.0.0.1:3307", database="docs", user="reader", password="wrong")
    assert env == {}  # a sign-in that did not work is forgotten again
    here["dbs"]["books"] = {"tables": {}}
    with pytest.raises(Refusal, match="to database 'books' \\(1044\\)"):
        plugin.connect_to("books", "127.0.0.1:3307", database="books", user="reader", password="r-secret")
    got = plugin.connect_to("docs", "127.0.0.1:3307", database="docs", holds="documents", user="reader", password="r-secret")
    assert got["ok"] and got["said"] == "docs connected: 127.0.0.1:3307/docs"
    assert got["lines"][:2] == ["MariaDB 11.4.3 at 127.0.0.1:3307, signed in as reader", "docs: 2 tables (filings, news)"]
    assert servers.given[-1] == {"user": "reader", "password": "r-secret", "host": "127.0.0.1", "database": "docs",
                                 "unix_socket": None, "port": 3307, "charset": "utf8mb4", "ssl": None,
                                 "connect_timeout": 5, "read_timeout": 5, "write_timeout": 5, "autocommit": False,
                                 "program_name": "liminal"}
    inst = plugin.instance("docs")
    assert (inst.port, inst.database, inst.auth, inst.role, inst.remote, inst.tls, inst.method) == (
        3307, "docs", True, "reader", False, False, "tcp")
    assert plugin.state(inst)["state"] == "listening" and plugin.test("docs")["ok"]
    kept = env["MARIADB_INSTANCES"]
    assert "secret" not in kept and "secret" not in json.dumps(plugin.status()) and "secret" not in json.dumps(got)
    assert env["MARIADB_DOCS_USER"] == "reader" and env["MARIADB_DOCS_PASSWORD"] == "r-secret"
    # MySQL's servers answer the same, and are named so
    mysql = servers.at[("tcp", "127.0.0.1", 3306)] = server(version="8.4.3")
    mysql["dbs"]["other"] = {"tables": {}}
    got = plugin.connect_to("other", "127.0.0.1", database="other", user="root", password="admin-secret")
    assert got["said"] == "other connected: 127.0.0.1:3306/other" and got["lines"][0].startswith("MySQL 8.4.3 at 127.0.0.1:3306")
    # moved to another port: kept only when it answers there
    servers.at[("tcp", "127.0.0.1", 3310)] = here
    assert plugin.set_port("docs", 3310)["said"] == "docs's port is 3310 now"
    with pytest.raises(Refusal, match="so docs's port stays 3310"):
        plugin.set_port("docs", 3311)
    del env["MARIADB_DOCS_PASSWORD"]
    before = len(servers.given)
    assert "docs's sign-in is not in the login" in plugin.test("docs")["said"] and len(servers.given) == before
    gone = plugin.forget("docs")
    assert gone["lines"][0] == "127.0.0.1:3310/docs stays as it is: nothing of it was removed"
    assert "MARIADB_DOCS_USER" not in env and "filings" in here["dbs"]["docs"]["tables"]


def test_opened_it_reads_only_unless_asked_to_write_and_is_the_callers_to_close(mys):
    plugin, servers, env = mys
    here = servers.at[("tcp", "127.0.0.1", 3306)] = server()
    here["dbs"]["docs"] = {"tables": {MARKER: []}}
    plugin.connect_to("docs", "127.0.0.1", database="docs", user="root", password="admin-secret")
    reading = plugin.open(plugin.instance("docs"))
    assert reading.read_only and reading.database == "docs" and reading.user == "root" and not reading.closed
    with pytest.raises(OperationalError, match="READ ONLY transaction"):
        reading.cursor().execute(f"INSERT INTO {MARKER} (id, name, made, holds, made_by) VALUES (%s, %s, %s, %s, %s)",
                                 ("x", "x", "x", "[]", "x"))
    writing = plugin.open(plugin.instance("docs"), read_only=False)
    assert not writing.read_only
    for c in (reading, writing):
        c.close()
    del env["MARIADB_DOCS_PASSWORD"]
    with pytest.raises(PermissionError, match="sign-in is not in the login"):
        plugin.open(plugin.instance("docs"))


def test_a_server_off_this_machine_is_kept_only_when_asked_twice_over_tls_checked_and_signed_in(mys):
    plugin, servers, env = mys
    far = servers.at[("tcp", "db.example.net", 3306)] = server(tls=True)
    far["users"][("reader", "%")] = {"password": "far-secret"}
    far["dbs"]["docs"] = {"tables": {}}
    far["grants"][("reader", "%")] = {"docs"}
    with pytest.raises(Refusal, match="db.example.net is not this machine") as first:
        plugin.connect_to("far", "db.example.net", database="docs", tls=True, user="reader", password="far-secret")
    assert first.value.accept == "accept_remote" and env == {} and servers.given == []
    with pytest.raises(Refusal, match="only with TLS and a sign-in"):
        plugin.connect_to("far", "db.example.net", database="docs", accept_remote=True, user="reader", password="far-secret")
    got = plugin.connect_to("far", "db.example.net", database="docs", tls=True, accept_remote=True, user="reader",
                            password="far-secret")
    assert got["lines"][0] == "MariaDB 11.4.3 at db.example.net:3306, signed in as reader, over TLS"
    context = servers.given[-1]["ssl"]
    assert isinstance(context, ssl.SSLContext) and context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    inst = plugin.instance("far")
    assert inst.remote and inst.tls and inst.auth and plugin.state(inst)["state"] == "not asked"  # a status never asks it
    assert plugin.test("far")["ok"]  # a test the user starts does


def test_a_socket_is_linuxs_alone(mys, monkeypatch):
    plugin, servers, env = mys
    if not module.SOCKETS:  # Windows: tcp alone, and said
        assert plugin.METHODS == ("tcp",) and "not offered on Windows" in plugin.api_facts()["MariaDB"]["Methods here"]
        with pytest.raises(Refusal, match="is reached by tcp: not 'socket'"):
            plugin.connect_to("local", "/run/mysqld/mysqld.sock", database="docs")
    monkeypatch.setattr(module, "SOCKETS", True)  # as on Linux (WSL too)
    monkeypatch.setattr(plugin, "METHODS", ("tcp", "socket"))
    here = servers.at[("socket", "/run/mysqld/mysqld.sock")] = server()
    here["users"][("ciara", "localhost")] = {"password": None, "super": True}  # unix_socket: this machine's user
    here["dbs"]["docs"] = {"tables": {}}
    got = plugin.connect_to("local", "/run/mysqld/mysqld.sock", database="docs")
    assert got["lines"][0] == "MariaDB 11.4.3 at /run/mysqld/mysqld.sock" and got["said"] == (
        "local connected: /run/mysqld/mysqld.sock (docs)")
    given = servers.given[-1]
    assert (given["unix_socket"], given["host"], given["ssl"], given["user"]) == ("/run/mysqld/mysqld.sock", None, None, "ciara")
    assert plugin.instance("local").method == "socket" and plugin.state(plugin.instance("local"))["state"] == "not asked"
    # a database made over the socket: its account signs in from localhost
    made = plugin.new_database("notes", "/run/mysqld/mysqld.sock", admin_user="ciara")
    assert made["ok"] and here["made"] == [("CREATE", "liminal_notes", "localhost")]
    assert here["grants"][("liminal_notes", "localhost")] == {"notes"}
    monkeypatch.setattr(module, "SOCKETS", False)  # a socket instance read where there is none: said, nothing tried
    assert "not offered on Windows" in plugin.test("local")["said"]


def test_a_new_database_gets_an_account_of_its_own_with_every_privilege_on_it_alone(mys):
    plugin, servers, env = mys
    with pytest.raises(Refusal, match="nothing listens at 127.0.0.1:3306.*a database is made on a server that runs"):
        plugin.new_database("notes", admin_user="root", admin_password="admin-secret")
    here = servers.at[("tcp", "127.0.0.1", 3306)] = server()
    with pytest.raises(Refusal, match="give the administrator's name"):
        plugin.new_database("notes")
    with pytest.raises(Refusal, match="127.0.0.1:3306 refused the administrator's sign-in: nothing was made"):
        plugin.new_database("notes", admin_user="root", admin_password="nope")
    with pytest.raises(Refusal, match="there is a database mysql on 127.0.0.1:3306 already: Connect keeps one"):
        plugin.new_database("again", database="mysql", admin_user="root", admin_password="admin-secret")
    assert env == {} and plugin.instances() == () and here["made"] == []
    made = plugin.new_database("filings-2026", database="filings", holds="documents", admin_user="root",
                               admin_password="admin-secret")
    assert made["ok"] and made["said"] == "filings-2026 made: 127.0.0.1:3306/filings"
    assert made["lines"][0] == f"the database filings made on 127.0.0.1:3306 (utf8mb4; its {MARKER} table says what it is)"
    assert made["lines"][1].startswith("the account liminal_filings_2026@% made for it (ALL PRIVILEGES on filings alone)")
    assert here["made"] == [("CREATE", "liminal_filings_2026", "%")]
    assert here["grants"][("liminal_filings_2026", "%")] == {"filings"}
    (row,) = here["dbs"]["filings"]["tables"][MARKER]
    inst = plugin.instance("filings-2026")
    assert row == {"id": "instance", "name": "filings-2026", "made": inst.at, "holds": '["documents"]',
                   "made_by": f"plugin-platform-mariadb {__version__}"}
    assert inst.made and inst.auth and (inst.role, inst.grants, inst.database, inst.holds) == (
        "liminal_filings_2026", ("ALL PRIVILEGES",), "filings", ("documents",))
    password = env["MARIADB_FILINGS_2026_PASSWORD"]
    assert here["users"][("liminal_filings_2026", "%")] == {"password": password} and len(password) >= 24
    everything = json.dumps(env) + json.dumps(made) + json.dumps(plugin.status())
    assert "admin-secret" not in everything
    assert password not in json.dumps(made) + json.dumps(plugin.status()) + env["MARIADB_INSTANCES"]
    tested = plugin.test("filings-2026")
    assert tested["lines"] == ["MariaDB 11.4.3 at 127.0.0.1:3306, signed in as liminal_filings_2026",
                               f"filings: 1 table ({MARKER})", f"made here on {inst.at[:10]} to hold documents"]
    admin = [c for c in servers.connections if c.user == "root"]
    assert admin and all(c.database is None and c.given["autocommit"] for c in admin)


def test_a_make_whose_marker_was_not_written_is_taken_back_whole_and_its_retry_finishes(mys):
    plugin, servers, env = mys
    here = servers.at[("tcp", "127.0.0.1", 3306)] = server(insert_fails=1)
    given = {"admin_user": "root", "admin_password": "admin-secret"}
    with pytest.raises(Exception, match="Lost connection to server during query"):
        plugin.new_database("filings", **given)
    assert here["dropped"] == [("database", "filings"), ("user", "liminal_filings", "%")]
    assert "filings" not in here["dbs"] and ("liminal_filings", "%") not in here["users"]
    assert env == {} and plugin.instances() == ()  # neither half a sign-in nor an instance
    assert plugin.new_database("filings", **given)["ok"] and here["dbs"]["filings"]["tables"][MARKER][0]["name"] == "filings"
    # the undoing did not reach the server either: the retry finds the account and an empty database, and finishes
    here["insert_fails"], here["drop_fails"] = 1, True
    with pytest.raises(Exception, match="Lost connection"):
        plugin.new_database("notes", **given)
    assert ("liminal_notes", "%") in here["users"] and "notes" in here["dbs"] and "MARIADB_NOTES_PASSWORD" not in env
    here["drop_fails"] = False
    made = plugin.new_database("notes", **given)
    assert made["ok"] and made["lines"][2:4] == [
        "the database notes was there from a make that stopped half way: finished",
        "the account liminal_notes was there from a make that stopped half way: taken over, its password renewed"]
    assert here["made"][-1] == ("ALTER", "liminal_notes", "%")
    assert here["users"][("liminal_notes", "%")] == {"password": env["MARIADB_NOTES_PASSWORD"]}
    assert plugin.test("notes")["lines"][0] == "MariaDB 11.4.3 at 127.0.0.1:3306, signed in as liminal_notes"
    # one made whole, then forgotten: its database stays, and a new one of that name is never made over it
    plugin.forget("notes")
    with pytest.raises(Refusal, match="there is a database notes on 127.0.0.1:3306 already"):
        plugin.new_database("notes", **given)
    # and one holding tables of somebody else's, beside an account of that name, neither
    here["dbs"]["theirs"] = {"tables": {"ledger": []}}
    here["users"][("liminal_theirs", "%")] = {"password": "x"}
    with pytest.raises(Refusal, match="there is a database theirs on 127.0.0.1:3306 already"):
        plugin.new_database("theirs", **given)


def test_an_account_whose_password_could_not_be_kept_is_taken_back_and_no_database_made(mys):
    plugin, servers, env = mys
    here = servers.at[("tcp", "127.0.0.1", 3306)] = server()

    class Full(EnvironmentLogin):
        def save(self, variable, value):
            if variable.endswith("_PASSWORD") and value:
                raise Unauthorized("no room for it", 500)
            return super().save(variable, value)

    plugin.attach(plugin.app, Full(env=env))
    with pytest.raises(Unauthorized, match="no room for it"):
        plugin.new_database("filings", admin_user="root", admin_password="admin-secret")
    assert here["dropped"] == [("user", "liminal_filings", "%")] and ("liminal_filings", "%") not in here["users"]
    assert "filings" not in here["dbs"] and env == {} and plugin.instances() == ()


def test_what_it_gives_the_driver_is_what_the_real_pymysql_takes(mys):
    """The stand-in must not drift from the driver: every connection given above binds to PyMySQL's own Connection
    (read from the installed package, nothing connected)."""
    plugin, servers, env = mys
    import importlib
    import importlib.util
    import inspect

    del sys.modules["pymysql"]
    try:
        if importlib.util.find_spec("pymysql") is None:
            pytest.skip("PyMySQL is not installed here")
        real = importlib.import_module("pymysql")
        signature = inspect.signature(real.connections.Connection.__init__)
        here = servers.at[("tcp", "127.0.0.1", 3306)] = server()
        given = []
        stand_in, kept = fake_driver(servers), module.my_connect
        try:
            module.my_connect = lambda **k: (given.append(k), stand_in.connect(**k))[1]
            plugin.new_database("notes", admin_user="root", admin_password="admin-secret")
            assert plugin.test("notes")["ok"]
        finally:
            module.my_connect = kept
        assert len(given) == 3  # the administrator's, the marker's, the account's own
        for k in given:
            signature.bind(None, program_name="liminal", charset=module.CHARSET, **k)
    finally:
        for name in [n for n in sys.modules if n == "pymysql" or n.startswith("pymysql.")]:
            del sys.modules[name]
