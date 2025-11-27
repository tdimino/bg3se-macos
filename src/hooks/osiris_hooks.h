/**
 * BG3SE-macOS - Osiris Engine Hooks Header
 */

#ifndef OSIRIS_HOOKS_H
#define OSIRIS_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Install hooks using fishhook library
 * Returns 0 on success, non-zero on failure
 */
int install_osiris_hooks(void);

/**
 * Install hooks using direct dlsym (alternative method)
 * Requires handle from dlopen on libOsiris.dylib
 */
int install_osiris_hooks_direct(void *osiris_handle);

/**
 * Check if hooks have been installed
 */
int are_hooks_installed(void);

#ifdef __cplusplus
}
#endif

#endif // OSIRIS_HOOKS_H
