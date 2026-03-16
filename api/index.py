import sys
import os
from pathlib import Path

# Add the project root to Python path
sys.path.append(str(Path(__file__).parent.parent))

from app import app

# Vercel serverless handler
def handler(request, **kwargs):
    with app.request_context(request):
        return app.full_dispatch_request()

# Export the app for Vercel
app = app
