"""GraphQL introspection + depth/batching abuse — API9:2023 Improper Inventory Management."""
import httpx


def run(base_url: str) -> dict:
    tests = []
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
    gql_url = None

    # Discover GraphQL endpoint
    for path in gql_paths:
        try:
            r = httpx.post(
                f"{base_url}{path}",
                json={"query": "{ __typename }"},
                timeout=8,
            )
            if r.status_code == 200 and ("__typename" in r.text or "data" in r.text):
                gql_url = f"{base_url}{path}"
                break
        except Exception:
            continue

    if not gql_url:
        tests.append({
            "test": "GraphQL endpoint discovery",
            "request": f"POST {gql_paths[0]} (probe)",
            "expected": "GraphQL endpoint present",
            "actual": "No GraphQL endpoint found at common paths — not applicable",
            "vulnerable": False,
            "severity": "LOW",
        })
        return {"category": "API9:2023 - Improper Inventory Management (GraphQL)", "tests": tests,
                "vulnerable_count": 0, "total": len(tests)}

    # Test 1: Introspection enabled
    try:
        r = httpx.post(gql_url, json={"query": "{ __schema { types { name } } }"}, timeout=8)
        schema_exposed = r.status_code == 200 and "__schema" in r.text and "types" in r.text
        tests.append({
            "test": "GraphQL introspection enabled",
            "request": f"POST {gql_url} — introspection query",
            "expected": "400 or error — introspection disabled in production",
            "actual": f"{r.status_code} — {'full schema returned' if schema_exposed else 'introspection disabled'}",
            "vulnerable": schema_exposed,
            "severity": "MEDIUM",
        })
    except Exception as e:
        tests.append({"test": "GraphQL introspection enabled", "request": f"POST {gql_url}",
                      "expected": "introspection disabled", "actual": f"Error: {e}",
                      "vulnerable": False, "severity": "MEDIUM"})

    # Test 2: Query depth / batching abuse (DoS)
    try:
        deep_query = "{ users { posts { comments { author { posts { comments { author { id } } } } } } } }"
        r = httpx.post(gql_url, json={"query": deep_query}, timeout=10)
        depth_vuln = r.status_code == 200 and "errors" not in r.text.lower()
        tests.append({
            "test": "GraphQL unbounded query depth",
            "request": f"POST {gql_url} — deeply nested query (7 levels)",
            "expected": "400 or depth-limit error",
            "actual": f"{r.status_code} — {'no depth limit enforced' if depth_vuln else 'depth limit rejected query'}",
            "vulnerable": depth_vuln,
            "severity": "MEDIUM",
        })
    except Exception as e:
        tests.append({"test": "GraphQL unbounded query depth", "request": f"POST {gql_url}",
                      "expected": "depth limit enforced", "actual": f"Error: {e}",
                      "vulnerable": False, "severity": "MEDIUM"})

    # Test 3: Batch query abuse
    try:
        batch = [{"query": "{ __typename }"}] * 50
        r = httpx.post(gql_url, json=batch, timeout=10)
        batch_vuln = r.status_code == 200
        tests.append({
            "test": "GraphQL query batching abuse (50 requests)",
            "request": f"POST {gql_url} — array of 50 queries",
            "expected": "400 or batch-limit error",
            "actual": f"{r.status_code} — {'batch accepted (DoS risk)' if batch_vuln else 'batch rejected'}",
            "vulnerable": batch_vuln,
            "severity": "MEDIUM",
        })
    except Exception as e:
        tests.append({"test": "GraphQL query batching abuse", "request": f"POST {gql_url}",
                      "expected": "batch limit enforced", "actual": f"Error: {e}",
                      "vulnerable": False, "severity": "MEDIUM"})

    return {
        "category": "API9:2023 - Improper Inventory Management (GraphQL)",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
