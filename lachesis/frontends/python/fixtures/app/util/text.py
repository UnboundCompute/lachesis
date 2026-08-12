"""Text helpers.

This file deliberately contains non-ASCII literals. CPython's ``ast`` reports
column offsets as UTF-8 byte counts into the physical line, while nav slices the
decoded text by character, so every function below is a regression anchor for the
byte-to-character conversion in emit.SourceFile.
"""

SEPARATOR = " · "
GREETING = "héllo"


def greet(name):
    """Return a greeting whose literal is wider in bytes than in characters."""
    prefix = "café"
    return f"{prefix}{SEPARATOR}{name}"


def shout(message, suffix="‼"):
    return message.upper() + suffix


def normalize(value):
    return " ".join(str(value).split())


# Everything below sits to the RIGHT of a non-ASCII character on its own line, so
# its ast column offset (bytes) and its real column (characters) disagree. These
# are the nodes that would be sliced wrong without the conversion.
def banner(title="✦", width=40, marker="•"):
    return f"{marker}{title:^{width}}{marker}"


ARROW = "→"; POINTER = "➜"
