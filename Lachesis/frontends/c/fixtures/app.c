#include "framework/router.h"

static int serve_document(const char *path) {
    return path[0] == '/' ? 200 : 404;
}

int configure_application(router *app) {
    route_register(app, serve_document);
    return app->handler("/documents");
}
