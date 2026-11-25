"""MariaDB for Liminal: databases on MariaDB servers that already run (MySQL's too, which speak the same protocol),
connected, or made there with an account of their own (a database plugin, plugin API 2.3: liminal_libs.storage.databases;
the platform's, drawn in its Databases section; Monday list item 13, item 30's step 6).

The user, 2026-11-15: "for the integrator i need plugins for each type of database and in each plugin can setup either
new databases or connections to existing databases using many different types of IP or IPC methods. each instance in
the plugin has it's own configuration how it's shared, ports, permissions etc"; "make sure to include integrator plugins
for postgres and mariadb" "alongside existing used databases".

It has no instance of its own and never starts a server: every instance is one you add. **Connect** keeps a database
on a server that runs, asked first and kept only when it answers. **New database** makes one on a server you name, with
an account of its own that has every privilege on that database and on no other: the administrator's name and password
are asked once and not kept; the account's password is made here, kept through the login and never shown. A sign-in is
two pairs through the login, never in a file. What an instance holds: documents first (the design of item 30: "documents
as their first store"); the stores that write there come with item 10.

Two methods. `tcp`: an address and a port (3306 unless given another); off this machine only when you say so twice,
and then over TLS (the server's certificate checked against its name) with a sign-in. `socket`: a Unix socket, on
Linux (WSL too): its whole file (/run/mysqld/mysqld.sock). Windows has no Unix socket in Python and PyMySQL takes no
named pipe, so on Windows it is tcp alone, and the plugin says so.

An account is a name and the host it signs in from: one made here signs in from any host ('%') when it is reached by
tcp, its password and its one database's grant keeping it in, and from 'localhost' when it is reached by a socket.

The driver is PyMySQL (pure Python), loaded only when a server is asked; without it the plugin says "driver not
installed" and everything else works. The plugin keeps no shares: who reaches a server is the server's to decide (its
accounts and their grants, bind_address). A status asks this machine alone whether anything listens; another machine
is asked only by a test you start."""
from __future__ import annotations

import getpass
import json
import socket
import ssl
from importlib import metadata
from pathlib import Path

from liminal_libs.storage import databases
from liminal_libs.storage.databases import DatabasePlugin, Instance, Made, Refusal, new_password, now_iso, variable_of

from .apis import APIS, MARIADB

__version__ = "0.1.0"
PORT = 3306  # the engine's usual port (databases.PORTS)
MARKER = "liminal_instance"  # the table a database made here says what it is in
GRANTS = ("ALL PRIVILEGES",)  # what the account made with a new database may do there, and nowhere else
TIMEOUT_S = 5  # a connection's wait, and each question's
REFUSED = (1045,)  # the server's code for a sign-in it refuses (ER_ACCESS_DENIED_ERROR)
SOCKETS = hasattr(socket, "AF_UNIX")  # a Unix socket in this Python (Linux, WSL; never Windows')
NO_SOCKET = ("a Unix socket is not offered on Windows: Python has none there and PyMySQL takes no named pipe, so a "
             "server is reached by tcp")
CHARSET = "utf8mb4"
COLLATION = "utf8mb4_unicode_ci"


class ServerError(Exception):
    """What a server or the driver said, in its words, with the server's code when it gave one."""

    def __init__(self, words: str, code: int | None = None):
        super().__init__(words)
        self.code = code


def said(e: BaseException) -> BaseException:
    """A driver's failure in words: PyMySQL gives the server's code and its message (OperationalError(1045, "Access
    denied ...")). The plugin's own refusals pass unchanged."""
    if isinstance(e, (Refusal, PermissionError, ServerError)):
        return e
    if len(e.args) >= 2 and isinstance(e.args[0], int) and isinstance(e.args[1], str):
        return ServerError(f"{' '.join(e.args[1].split())} ({e.args[0]})", e.args[0])
    return ServerError(" ".join(str(e).split()) or type(e).__name__)


def my_connect(**given):
    """A DB-API connection of PyMySQL's, for one question; closed by whoever asked. (A module name, so a test stands one
    in; the driver is loaded here, when a server is asked, and only then.)"""
    import pymysql

    return pymysql.connect(program_name="liminal", charset=CHARSET, **given)


def driver() -> str:
    """The PyMySQL this Python carries, by its package's word (nothing is loaded to say it); "" when it has none."""
    try:
        return metadata.version("PyMySQL")
    except metadata.PackageNotFoundError:
        return ""


def identifier(name: str) -> str:
    """A name in a statement, quoted (a database's; DATABASE has let only letters, digits, _ and - by)."""
    return "`" + name.replace("`", "``") + "`"


def literal(text: str) -> str:
    """A string in a statement that takes no parameters (an account's name, host and password), quoted as MariaDB reads
    it in every sql_mode: a backslash and a quote doubled."""
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


def account_of(instance: str) -> str:
    return f"liminal_{instance.replace('-', '_')}"


def host_of(instance: Instance) -> str:
    """The host an account made here signs in from: 'localhost' over a socket, any ('%') over tcp."""
    return "localhost" if instance.method == "socket" else "%"


def _refused(e: BaseException) -> bool:
    return getattr(e, "code", None) in REFUSED


class MariadbPlugin(DatabasePlugin):
    name = "mariadb"
    title = "MariaDB"
    about = ("Databases on MariaDB (or MySQL) servers that already run: connected, or made there with an account of "
             "their own; never a server started")
    api = "2.3"
    order = 704
    options = (variable_of("mariadb"),)  # MARIADB_INSTANCES: what you add
    apis = APIS
    ENGINE = "mariadb"
    METHODS = ("tcp", "socket") if SOCKETS else ("tcp",)
    HOLDS = ("documents",)
    SERVER = True
    DRIVER = "pymysql"
    DRIVER_HINT = "driver not installed: PyMySQL is not in the app's Python (this plugin's own dependency: pip install PyMySQL)"
    SHARES = False
    SHARED = ("a server's own to decide (its accounts, their grants, and the addresses it listens on): the plugin reaches "
              "it with the account you give it, and a database it makes is that account's alone")

    # -- a connection ------------------------------------------------------------------------------------------------
    def _connect(self, instance: Instance, user: str | None = None, password: str | None = None,
                 database: str | None = "", autocommit: bool = False):
        """A connection to `instance`'s server, signed in as given or as the instance says (its pairs from the login;
        with none, this machine's user, as MariaDB's own clients do), to `database` (None: none) or the instance's."""
        if user is None:
            got = self.credentials(instance) if instance.auth else None
            if instance.auth and got is None:
                raise PermissionError(f"{instance.name}'s sign-in is not in the login: set its name and password again")
            user, password = got or (None, None)
        given = {"user": user or _os_user(), "password": password or "",
                 "database": (database or instance.database) if database is not None else None,
                 "connect_timeout": TIMEOUT_S, "read_timeout": TIMEOUT_S, "write_timeout": TIMEOUT_S,
                 "autocommit": autocommit}
        if instance.method == "socket":
            if not SOCKETS:
                raise Refusal(NO_SOCKET)
            given.update(unix_socket=instance.where)
        else:
            # over TLS: the server's certificate checked against its name; else plain, which only this machine's are
            given.update(host=instance.where, port=instance.port or PORT,
                         ssl=ssl.create_default_context() if instance.tls else None)
        try:
            return my_connect(**given)
        except Exception as e:  # noqa: BLE001 - the server's or the driver's refusal, in words
            raise said(e) from None

    def _listens(self, instance: Instance) -> None:
        """ConnectionError when nothing listens at a server of this machine (asked now, not as a status remembered
        it). A socket, and another machine, are not asked here: the driver says."""
        port = instance.port or PORT
        if instance.method == "tcp" and databases.is_local(instance.where) and not databases.listening(
                instance.where, port, fresh=True):
            raise ConnectionError(f"nothing listens at {instance.where}:{port}: the plugin starts no server")

    # -- the hooks ---------------------------------------------------------------------------------------------------
    def builtin(self, data_dir: Path) -> tuple[Instance, ...]:
        return ()  # no server of its own: every instance is one you add

    def open(self, instance: Instance, part: str = "", read_only: bool = True, data_dir: Path | None = None):
        """A DB-API connection (PyMySQL's) to the instance's database, signed in as its account; closed by whoever
        asked. `read_only` (the default) is kept by the server itself: the session's transactions read only. `part` is
        not used by a server's engine (a table is named in the statements)."""
        conn = self._connect(instance)
        if read_only:
            try:
                conn.cursor().execute("SET SESSION TRANSACTION READ ONLY")
            except Exception as e:  # noqa: BLE001 - not handed out unless it reads only
                conn.close()
                raise said(e) from None
        return conn

    def probe(self, instance: Instance, data_dir: Path) -> list[str]:
        self._listens(instance)
        conn = self._connect(instance)
        try:
            cur = conn.cursor()
            cur.execute("SELECT VERSION()")
            version = str(cur.fetchone()[0] or "?")
            names = _tables(cur)
            made = None
            if MARKER in names:
                cur.execute(f"SELECT made, holds FROM {MARKER} WHERE id = %s", ("instance",))
                made = cur.fetchone()
            conn.rollback()
        except Exception as e:  # noqa: BLE001 - in its words
            raise said(e) from None
        finally:
            conn.close()
        lines = [f"{_engine(version)} at {_where(instance)}" + (f", signed in as {instance.role}" if instance.auth else "")
                 + (", over TLS" if instance.tls else ""),
                 f"{instance.database}: {len(names)} table{'' if len(names) == 1 else 's'}"
                 + (f" ({', '.join(names[:6])}{', ...' if len(names) > 6 else ''})" if names else "")]
        if made:
            lines.append(f"made here on {str(made[0] or '?')[:10]} to hold {', '.join(_holds(made[1])) or 'nothing yet'}")
        return lines

    def make(self, instance: Instance, data_dir: Path, admin_user: str = "", admin_password: str = "", **given) -> Made:
        where, name = _where(instance), instance.database
        try:
            self._listens(instance)
        except ConnectionError as e:
            raise Refusal(f"{e}: a database is made on a server that runs") from None
        if not admin_user:
            raise Refusal("the server's administrator makes a database and its account: give the administrator's name "
                          "(and password), asked this once and not kept")
        try:
            admin = self._connect(instance, admin_user, admin_password, None, autocommit=True)
        except ServerError as e:
            if _refused(e):
                raise Refusal(f"{where} refused the administrator's sign-in: nothing was made") from None
            raise
        user, host, password, lines = account_of(instance.name), host_of(instance), new_password(), []
        account = f"{literal(user)}@{literal(host)}"
        try:
            cur = admin.cursor()
            try:
                cur.execute("SELECT 1 FROM mysql.user WHERE User = %s AND Host = %s", (user, host))
                there = cur.fetchone() is not None
                cur.execute("SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s", (name,))
                exists = cur.fetchone() is not None
                # A database holding nothing (its marker empty or not there) beside this instance's account is an
                # earlier make's that stopped half way and whose undoing did not reach the server either: this make
                # finishes it rather than failing for good (as plugin-platform-mongodb 0.1.1 learned). Any other is
                # never made over.
                half = exists and there and self._empty(cur, name)
                if exists and not half:
                    raise Refusal(f"there is a database {name} on {where} already: Connect keeps one that exists")
                verb = "ALTER" if there else "CREATE"
                cur.execute(f"{verb} USER {account} IDENTIFIED BY {literal(password)}")
            except Exception as e:  # noqa: BLE001 - in its words
                raise said(e) from None
            if half:
                lines.append(f"the database {name} was there from a make that stopped half way: finished")
            if there:
                lines.append(f"the account {user} was there from a make that stopped half way: taken over, its password "
                             "renewed")
            try:
                self.keep_credentials(instance.name, user, password)
            except Exception:
                _quietly(cur, f"DROP USER IF EXISTS {account}")  # an account nobody holds the password of is taken back
                raise
            try:
                if not half:
                    cur.execute(f"CREATE DATABASE {identifier(name)} CHARACTER SET {CHARSET} COLLATE {COLLATION}")
                cur.execute(f"GRANT ALL PRIVILEGES ON {identifier(name)}.* TO {account}")
                self._mark(instance, user, password)
            except Exception as e:
                # No database without its marker, so nothing half made is left: the database, the account and its
                # kept sign-in are taken back (a retry takes over an account whose dropping did not reach the server).
                _quietly(cur, f"DROP DATABASE IF EXISTS {identifier(name)}")
                _quietly(cur, f"DROP USER IF EXISTS {account}")
                self._forget_credentials(instance.name)
                raise said(e) from None
        finally:
            admin.close()
        return Made((f"the database {name} made on {where} ({CHARSET}; its {MARKER} table says what it is)",
                     f"the account {user}@{host} made for it (ALL PRIVILEGES on {name} alone); its password kept through "
                     "the login, never shown", *lines), role=user, grants=GRANTS)

    @staticmethod
    def _empty(cur, name: str) -> bool:
        """Whether a database there holds nothing: no table but an empty marker. False when it cannot be told, so
        nothing is ever made over it."""
        try:
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (name,))
            tables = {str(r[0]) for r in cur.fetchall()}
            if not tables:
                return True
            if tables != {MARKER}:
                return False
            cur.execute(f"SELECT COUNT(*) FROM {identifier(name)}.{MARKER}")
            return int(cur.fetchone()[0]) == 0
        except Exception:  # noqa: BLE001
            return False

    def _mark(self, instance: Instance, user: str, password: str) -> None:
        """The new database says what it is, written by its own account."""
        conn = self._connect(instance, user, password, instance.database)
        try:
            cur = conn.cursor()
            cur.execute(f"CREATE TABLE IF NOT EXISTS {MARKER} (id VARCHAR(32) PRIMARY KEY, name VARCHAR(64) NOT NULL, "
                        "made VARCHAR(40) NOT NULL, holds TEXT NOT NULL, made_by VARCHAR(80) NOT NULL)")
            cur.execute(f"INSERT INTO {MARKER} (id, name, made, holds, made_by) VALUES (%s, %s, %s, %s, %s)",
                        ("instance", instance.name, instance.at or now_iso(), json.dumps(list(instance.holds)),
                         f"plugin-platform-mariadb {__version__}"))
            conn.commit()
        finally:
            conn.close()

    def api_facts(self) -> dict:
        """What is known of MariaDB here without asking any server: the driver this Python carries, and the methods
        this system offers."""
        return {MARIADB.name: {"PyMySQL in this Python": driver() or "driver not installed",
                               "Methods here": "tcp and a Unix socket" if SOCKETS else f"tcp alone ({NO_SOCKET})",
                               "Its own server": "none: it starts no server, every instance is one you add"}}


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no name for this machine's user: the server's usual administrator
        return "root"


def _where(instance: Instance) -> str:
    return instance.where if instance.method == "socket" else f"{instance.where}:{instance.port or PORT}"


def _engine(version: str) -> str:
    """The server's name and version from VERSION(): 11.4.3-MariaDB-ubu2404 is MariaDB 11.4.3; 8.4.0 is MySQL's."""
    number = version.split("-")[0]
    return f"MariaDB {number}" if "mariadb" in version.lower() else f"MySQL {number}"


def _tables(cur) -> list[str]:
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name")
    return [str(r[0]) for r in cur.fetchall()]


def _holds(text) -> list[str]:
    try:
        got = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    return [str(h) for h in got] if isinstance(got, list) else []


def _quietly(cur, statement: str) -> None:
    """An undoing: tried, and a server gone by now let be (a retry takes over what is left)."""
    try:
        cur.execute(statement)
    except Exception:  # noqa: BLE001
        pass


DATABASE = MariadbPlugin()
