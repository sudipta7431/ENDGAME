def enrich(endpoint):
    intel = []

    if "admin" in endpoint:
        intel.append("Admin surface")

    if "debug" in endpoint:
        intel.append("Debug exposure")

    if "internal" in endpoint:
        intel.append("Internal API pattern")

    if "graphql" in endpoint:
        intel.append("GraphQL attack surface")

    return intel
