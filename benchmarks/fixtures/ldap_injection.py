import ldap


def vulnerable(con, search_base, username):
    filter_str = f"(uid={username})"
    return con.search_s(search_base, ldap.SCOPE_SUBTREE, filter_str, ["uid"])


def patched(con, search_base, username):
    escaped_username = ldap.filter.escape_filter_chars(username)
    filter_str = f"(uid={escaped_username})"
    return con.search_s(search_base, ldap.SCOPE_SUBTREE, filter_str, ["uid"])
