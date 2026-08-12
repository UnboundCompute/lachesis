#ifndef LACHESIS_FIXTURE_ROUTER_H
#define LACHESIS_FIXTURE_ROUTER_H

typedef int (*route_handler)(const char *path);

typedef struct router {
    route_handler handler;
} router;

static inline void route_register(router *instance, route_handler handler) {
    instance->handler = handler;
}

#endif
