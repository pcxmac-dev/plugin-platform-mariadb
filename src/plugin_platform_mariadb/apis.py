"""What the MariaDB plugin attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): a MariaDB server (or MySQL's, the same protocol), through PyMySQL, a pure-Python driver.

Every address is one of MariaDB's own pages (its knowledge base on mariadb.com) or PyMySQL's (its documentation on
Read the Docs, its repository, its PyPI page). They were written on 2026-11-25 from what was known of those sites, not
fetched (`VERIFIED` is that day); MariaDB has been moving its knowledge base under mariadb.com/docs, and its old
addresses are meant to lead there. The one test that reaches the network, with LIMINAL_VENDOR_PAGES=1, says whether
each answers.

What those pages say and the plugin stands on: a server listens on 3306 unless given another port, at bind_address, and
on its Unix socket (socket); an account is a name and the host it signs in from, 'localhost' meaning a socket's; CREATE
USER, ALTER USER and GRANT take no parameters, so names and the password are written in the statement; ALL PRIVILEGES
on db.* is everything on that database and nothing beyond it, and no GRANT OPTION; a session's transactions can be made
read only."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-25"
KB = "https://mariadb.com/kb/en/"
DOCS = KB + "documentation/"
VARIABLES = KB + "server-system-variables/"
REMOTE = KB + "configuring-mariadb-for-remote-client-access/"
TLS = KB + "secure-connections-overview/"
ACCOUNTS = KB + "account-management-sql-commands/"
CREATE_USER = KB + "create-user/"
ALTER_USER = KB + "alter-user/"
DROP_USER = KB + "drop-user/"
GRANT = KB + "grant/"
CREATE_DATABASE = KB + "create-database/"
DROP_DATABASE = KB + "drop-database/"
USER_TABLE = KB + "mysql-user-table/"
SCHEMATA = KB + "information-schema-schemata-table/"
TABLES = KB + "information-schema-tables-table/"
VERSION = KB + "version/"
TRANSACTION = KB + "set-transaction/"
UNIX_SOCKET = KB + "authentication-plugin-unix-socket/"
NOTES = KB + "release-notes/"
LICENSE = KB + "mariadb-license/"
PYMYSQL = "https://pymysql.readthedocs.io/en/latest/"
PYMYSQL_CONNECTIONS = PYMYSQL + "modules/connections.html"
PYMYSQL_REPO = "https://github.com/PyMySQL/PyMySQL"
PYMYSQL_PYPI = "https://pypi.org/project/PyMySQL/"

MARIADB = Api(
    name="MariaDB",
    maker="The MariaDB Foundation and MariaDB plc (mariadb.org, mariadb.com); PyMySQL by its maintainers",
    about=("A relational database server, MySQL's descendant: databases of tables, reached over TCP or a Unix socket by a "
           "driver that speaks its protocol (MySQL's servers speak it too). The plugin reaches servers that already run "
           "through PyMySQL, a pure-Python driver (nothing compiled, the same in the WSL suite), and keeps documents "
           "there first."),
    kind="sdk",
    base="each instance's address: host:port (3306 unless given another), or a Unix socket on Linux",
    version="MariaDB 10.6 and newer (and MySQL 8), through PyMySQL",
    auth=("an account's name and password, kept through the login as two pairs; a server off this machine over TLS "
          "alone, its certificate checked against its name; who may sign in from where is the server's accounts"),
    limits="",
    costs="",
    links=(
        Link("MariaDB documentation", DOCS, "docs"),
        Link("Server System Variables: port, socket, bind_address", VARIABLES, "reference"),
        Link("Configuring MariaDB for Remote Client Access", REMOTE, "guide"),
        Link("Secure Connections Overview (TLS)", TLS, "guide"),
        Link("Account Management SQL Statements", ACCOUNTS, "reference"),
        Link("CREATE USER", CREATE_USER, "reference"),
        Link("GRANT", GRANT, "reference"),
        Link("CREATE DATABASE", CREATE_DATABASE, "reference"),
        Link("PyMySQL documentation", PYMYSQL, "sdk"),
        Link("PyMySQL's Connection object", PYMYSQL_CONNECTIONS, "sdk"),
        Link("PyMySQL's repository", PYMYSQL_REPO, "sdk"),
        Link("PyMySQL on PyPI", PYMYSQL_PYPI, "sdk"),
        Link("Release Notes", NOTES, "changelog"),
        Link("MariaDB License", LICENSE, "terms"),
    ),
    areas=(
        Area("Connections", "where a server listens: bind_address, its port, its Unix socket", VARIABLES,
             covered="an instance is an address and a port (3306 unless given another), or a socket on Linux; one off "
                     "this machine is kept only when asked twice"),
        Area("Remote access", "a server reachable from other machines, and the accounts that may sign in from them",
             REMOTE, covered="the server's own: the plugin keeps no shares, and says so"),
        Area("TLS", "a connection encrypted, the server's certificate checked by the client", TLS,
             covered="an instance off this machine is reached over TLS alone, the certificate checked against its name"),
        Area("Accounts and privileges", "who signs in from where, and what each account may do", ACCOUNTS,
             covered="a database made here gets an account of its own with ALL PRIVILEGES on it alone (no GRANT "
                     "OPTION); a sign-in is two pairs through the login"),
        Area("Databases", "a database made, dropped, listed", CREATE_DATABASE,
             covered="New database (utf8mb4): never over one that is there; a make that fails is taken back whole"),
        Area("Information schema", "what a server says of itself: its databases, a database's tables", TABLES,
             covered="Test reads the version and the tables; New database asks the databases and the accounts first"),
        Area("Transactions", "a session's transactions read only, or reading and writing", TRANSACTION,
             covered="a connection opened for reading is read only on the server's side"),
        Area("The Python driver (PyMySQL)", "pymysql.connect and its cursors: host, port, unix_socket, ssl, timeouts, "
             "autocommit, program_name", PYMYSQL_CONNECTIONS,
             covered="every connection it opens: one server, short waits, closed after the question; loaded only when "
                     "a server is asked"),
        Area("Sizes", "a database's and a table's bytes on disk (information_schema.TABLES: data_length, index_length)",
             TABLES),
        Area("Socket authentication", "an account signed in by the machine's own user over a socket (unix_socket)",
             UNIX_SOCKET),
        Area("Replication and Galera", "several servers as one", DOCS),
    ),
    calls=(
        Call("pymysql.connect(host=, port=, user=, password=, database=, unix_socket=, ssl=, connect_timeout=, "
             "read_timeout=, write_timeout=, autocommit=, charset=, program_name=)", "a connection to one server, signed in",
             "The Python driver (PyMySQL)", used="every connection it opens, closed after the question",
             docs=PYMYSQL_CONNECTIONS),
        Call("SELECT VERSION()", "the server's version", "Information schema", used="Test: which MariaDB (or MySQL) answers",
             docs=VERSION),
        Call("information_schema.TABLES", "a database's tables", "Information schema", used="Test: what the database holds",
             docs=TABLES),
        Call("information_schema.SCHEMATA", "the databases a server has", "Information schema",
             used="New database: never over one that is there", docs=SCHEMATA),
        Call("mysql.user", "the accounts a server has", "Accounts and privileges",
             used="New database: an account left by a make that stopped half way is taken over", docs=USER_TABLE),
        Call("CREATE USER ... IDENTIFIED BY", "an account made, with its password", "Accounts and privileges",
             used="New database: the account of its own", docs=CREATE_USER, writes=True),
        Call("ALTER USER ... IDENTIFIED BY", "an account's password changed", "Accounts and privileges",
             used="New database: an account left half way taken over, its password renewed", docs=ALTER_USER, writes=True),
        Call("DROP USER IF EXISTS", "an account removed", "Accounts and privileges",
             used="the account taken back when its password could not be kept, or its database not made", docs=DROP_USER,
             writes=True),
        Call("GRANT ALL PRIVILEGES ON db.* TO", "every privilege on one database given to an account",
             "Accounts and privileges", used="New database: its account's grant, on it alone", docs=GRANT, writes=True),
        Call("CREATE DATABASE ... CHARACTER SET utf8mb4", "a database made", "Databases", used="New database",
             docs=CREATE_DATABASE, writes=True),
        Call("DROP DATABASE IF EXISTS", "a database removed", "Databases",
             used="a database whose marker could not be written taken back (never one it did not just make)",
             docs=DROP_DATABASE, writes=True),
        Call("CREATE TABLE liminal_instance, INSERT", "a table made, a row written", "Databases",
             used="a database made here says what it is in it: its name, the day, what it is to hold", writes=True),
        Call("SET SESSION TRANSACTION READ ONLY", "a session that reads only", "Transactions",
             used="a connection opened for reading", docs=TRANSACTION),
        Call("information_schema.TABLES data_length, index_length", "a table's bytes on disk", "Sizes", docs=TABLES),
    ),
    verified=VERIFIED,
)

APIS = (MARIADB,)
