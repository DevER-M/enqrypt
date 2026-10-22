"""enc - server-hosted chat with browser-side post-quantum encryption.

The FastAPI server in :mod:`enc.server` serves the web app and relays opaque
frames. All key generation and message encryption happens in the browser, in
``web/static/js``; the server never holds a key and never sees plaintext.
"""

__version__ = "0.2.0"
