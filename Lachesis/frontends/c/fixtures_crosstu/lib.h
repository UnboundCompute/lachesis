/* Cross-TU fixture: a public prototype with no body.
 *
 * Parsed as its own compiler root, this header yields a bodyless prototype node
 * (declaration_only=True) that twins the real definition in lib.c under the same
 * name. A caller in another TU (client.c) that only sees this prototype is what
 * the cross-TU linker must connect to the definition.
 */
#ifndef LIB_H
#define LIB_H

int lib_compute(int x);

#endif
