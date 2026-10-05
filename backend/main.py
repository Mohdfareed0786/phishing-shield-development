import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from config.settings import settings
from routes.history import router as history_router
from routes.profile import router as profile_router
from routes.scan import router as scan_router

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger('phishing_shield')
app = FastAPI(title=settings.app_name, version='1.0.0', docs_url='/docs' if not settings.is_production else None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'apikey'],
    max_age=600,
)


@app.middleware('http')
async def security_and_request_size_headers(request: Request, call_next):
    content_length = request.headers.get('content-length')
    if content_length:
        try:
            too_large = int(content_length) > settings.max_request_bytes
        except ValueError:
            too_large = True
        if too_large:
            return JSONResponse({'error': 'Request is too large.'}, status_code=413)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if settings.is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=63072000'
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, _exc: RequestValidationError):
    return JSONResponse({'error': 'Invalid request. Check the submitted URL or message and try again.'}, status_code=422)


@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, str) else 'The request could not be completed.'
    return JSONResponse({'error': detail}, status_code=exc.status_code, headers=exc.headers)


@app.exception_handler(Exception)
async def internal_error_handler(_request: Request, exc: Exception):
    logger.exception('Unhandled API error', exc_info=exc)
    return JSONResponse({'error': 'The security service encountered an unexpected error.'}, status_code=500)


@app.get('/healthz', tags=['health'])
async def health() -> dict[str, str]:
    return {'status': 'ok'}


app.include_router(scan_router)
app.include_router(history_router)
app.include_router(profile_router)
