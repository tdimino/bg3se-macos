# Find GetRawComponent - search by function name patterns
# @category BG3SE
# @description Search for GetRawComponent by name patterns and EntityWorld methods

"""
Search strategy:
1. Functions with "GetComponent", "GetRaw", "RawComponent" in name
2. Functions in EntityWorld class
3. Functions that access EntityStorageData
"""


def main():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    print("=" * 70)
    print("BG3SE GetRawComponent Finder v3 - Name Pattern Search")
    print("=" * 70)
    print("")

    # Categories to search
    getcomponent_funcs = []
    entityworld_funcs = []
    storage_funcs = []
    oneframe_funcs = []

    for func in fm.getFunctions(True):
        name = func.getName()
        name_lower = name.lower()
        addr = func.getEntryPoint()
        size = func.getBody().getNumAddresses()

        # Skip tiny functions
        if size < 50:
            continue

        # GetComponent patterns
        if 'getcomponent' in name_lower or 'getraw' in name_lower or 'rawcomponent' in name_lower:
            getcomponent_funcs.append({
                'addr': addr,
                'name': name,
                'size': size
            })

        # EntityWorld methods
        if 'entityworld' in name_lower:
            entityworld_funcs.append({
                'addr': addr,
                'name': name,
                'size': size
            })

        # Storage access
        if 'entitystorage' in name_lower and 'get' in name_lower:
            storage_funcs.append({
                'addr': addr,
                'name': name,
                'size': size
            })

        # OneFrame handling
        if 'oneframe' in name_lower:
            oneframe_funcs.append({
                'addr': addr,
                'name': name,
                'size': size
            })

    # Print results
    print("=" * 70)
    print("FUNCTIONS with 'GetComponent', 'GetRaw', 'RawComponent' in name")
    print("=" * 70)
    for f in sorted(getcomponent_funcs, key=lambda x: x['size'], reverse=True)[:30]:
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:90]))
    print("")

    print("=" * 70)
    print("ENTITYWORLD methods")
    print("=" * 70)
    for f in sorted(entityworld_funcs, key=lambda x: x['size'], reverse=True)[:30]:
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:90]))
    print("")

    print("=" * 70)
    print("ENTITYSTORAGE + 'Get' functions")
    print("=" * 70)
    for f in sorted(storage_funcs, key=lambda x: x['size'], reverse=True)[:20]:
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:90]))
    print("")

    print("=" * 70)
    print("ONEFRAME functions")
    print("=" * 70)
    for f in sorted(oneframe_funcs, key=lambda x: x['size'], reverse=True)[:20]:
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:90]))
    print("")

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("GetComponent/GetRaw functions: {}".format(len(getcomponent_funcs)))
    print("EntityWorld methods: {}".format(len(entityworld_funcs)))
    print("EntityStorage+Get functions: {}".format(len(storage_funcs)))
    print("OneFrame functions: {}".format(len(oneframe_funcs)))
    print("")
    print("Look for:")
    print("- EntityWorld::GetRawComponent or similar")
    print("- Functions taking (EntityHandle, ComponentTypeIndex, size, bool)")
    print("- Medium-sized functions (200-800 bytes) with multiple return paths")


if __name__ == "__main__":
    main()
