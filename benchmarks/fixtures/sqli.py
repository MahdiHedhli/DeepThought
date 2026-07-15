def vulnerable_lookup(request, cursor):
    query = request.GET.get("query", "")
    sql = "SELECT value FROM values WHERE LOWER(value)='{query}'"
    sql = sql.format(query=query.lower())
    cursor.execute(sql)


def parameterized_lookup(request, cursor):
    cursor.execute(
        "SELECT value FROM values WHERE LOWER(value)=%(query)s",
        {"query": request.GET.get("query", "").lower()},
    )
