# Find GetRawComponent - focus on ecs namespace and storage access patterns
# @category BG3SE
# @description Search for GetRawComponent in ecs namespace with storage patterns

"""
Based on bg3se reference:
- GetRawComponent calls GetEntityStorage
- Checks IsOneFrame (type & 0x8000)
- Returns component pointer

Look for functions that:
1. Are in ecs:: namespace
2. Have moderate size (100-1000 bytes)
3. Reference EntityStorageData or EntityHandle
"""


def main():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    print("=" * 70)
    print("BG3SE GetRawComponent Finder v4 - ECS Namespace Focus")
    print("=" * 70)
    print("")

    # Collect ECS namespace functions by category
    ecs_functions = []
    storage_access = []
    handle_functions = []

    for func in fm.getFunctions(True):
        name = func.getName()
        addr = func.getEntryPoint()
        size = func.getBody().getNumAddresses()

        # Only ecs:: namespace
        if not name.startswith('__ZN3ecs'):
            continue

        # Skip huge functions (registration, systems)
        if size > 2000 or size < 80:
            continue

        # Demangle to check for relevant patterns
        ecs_functions.append({
            'addr': addr,
            'name': name,
            'size': size
        })

        # Look for storage-related
        if 'storage' in name.lower() or 'Storage' in name:
            storage_access.append({
                'addr': addr,
                'name': name,
                'size': size
            })

        # Look for handle/entity access
        if 'handle' in name.lower() or 'Handle' in name or 'entity' in name.lower():
            handle_functions.append({
                'addr': addr,
                'name': name,
                'size': size
            })

    # Sort by size (medium-sized functions more likely)
    def score(f):
        # Prefer 200-600 byte functions
        if 200 <= f['size'] <= 600:
            return 1000 - abs(f['size'] - 400)
        return 0

    # Print storage functions (most likely candidates)
    print("=" * 70)
    print("ECS STORAGE FUNCTIONS (100-2000 bytes)")
    print("=" * 70)
    for f in sorted(storage_access, key=lambda x: x['size']):
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:85]))
    print("")

    # Print handle functions
    print("=" * 70)
    print("ECS HANDLE/ENTITY FUNCTIONS (100-2000 bytes)")
    print("=" * 70)
    for f in sorted(handle_functions, key=lambda x: x['size'])[:40]:
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:85]))
    print("")

    # Print all medium ecs functions
    print("=" * 70)
    print("ALL ECS NAMESPACE FUNCTIONS (200-600 bytes - sweet spot)")
    print("=" * 70)
    medium_funcs = [f for f in ecs_functions if 200 <= f['size'] <= 600]
    for f in sorted(medium_funcs, key=lambda x: x['size']):
        print("  {} ({:5d} bytes) {}".format(f['addr'], f['size'], f['name'][:85]))
    print("")

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Total ecs:: functions (100-2000 bytes): {}".format(len(ecs_functions)))
    print("Storage-related: {}".format(len(storage_access)))
    print("Handle/Entity-related: {}".format(len(handle_functions)))
    print("Medium size (200-600 bytes): {}".format(len(medium_funcs)))
    print("")
    print("Key candidates to inspect in Ghidra GUI:")
    print("- EntityStorageContainer::TryGet (0x10636b27c)")
    print("- Functions with 'GetComponent' pattern")
    print("- Functions taking EntityHandle parameter")


if __name__ == "__main__":
    main()
