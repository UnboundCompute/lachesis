"""Root-level entry module: absolute, namespace and unresolvable imports."""

import json

from app.service import run
from namespace.inner.leaf import identify
from acme.vendor.client import Client


def main(connection):
    return json.dumps({
        "result": run(connection, identify()),
        "client": Client.__name__,
    })
