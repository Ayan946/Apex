COMMON_PATHS = [
    "", "/api", "/api/v1", "/api/v2", "/users", "/user", "/admin",
    "/login", "/auth", "/token", "/config", "/health", "/status",
    "/swagger.json", "/openapi.json", "/docs", "/graphql"
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


def discover_surface(session, base_url, output_file=None):
    print(f"[INF] Mapping attack surface on {base_url}")
    found = []

    for path in COMMON_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=8)
            if r.status_code != 404:
                entry = f"[EP] {url} [{r.status_code}]"
                print(entry)
                if output_file:
                    output_file.write(entry + "\n")
                found.append(url)
        except Exception:
            continue

    allowed = check_methods(session, base_url, output_file)
    return {"endpoints": found, "allowed_methods": allowed}


def check_methods(session, url, output_file=None):
    try:
        r = session.options(url, timeout=8)
        allow = r.headers.get("Allow", "")
        if allow:
            entry = f"[MET] {url} allows: {allow}"
            print(entry)
            if output_file:
                output_file.write(entry + "\n")
            return allow.split(", ")
    except Exception:
        pass
    return []
