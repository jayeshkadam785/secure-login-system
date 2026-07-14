import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app import app  # noqa: E402

# Vercel's @vercel/python builder looks for a WSGI-compatible `app` object
# in this file. All routes are proxied here via vercel.json.
