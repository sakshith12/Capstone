# Vercel serverless function entry point
from api import app

# Vercel needs this
def handler(request, context):
    return app(request, context)
