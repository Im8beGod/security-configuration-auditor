from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import router as api_router
from app.core.config import ApplicationSettings, get_application_settings


def health_check():
    return {"status": "healthy"}


def create_app(settings: ApplicationSettings | None = None) -> FastAPI:
    routing_settings = settings if settings is not None else get_application_settings()
    application = FastAPI(title=routing_settings.app_name, version="0.1.0")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[routing_settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["DELETE", "GET", "PATCH", "POST", "PUT"],
        allow_headers=["Content-Type"],
    )

    @application.middleware("http")
    async def enforce_cookie_origin(request: Request, call_next):
        """Reject cross-origin state changes made with the auth cookie.

        Requests without the cookie are left alone for login and internal
        worker paths. Cookie-authenticated mutations must carry the exact
        configured frontend Origin, including same-origin browser requests.
        """
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            cookie = request.cookies.get(routing_settings.auth_cookie_name)
            origin = request.headers.get("origin")
            if cookie is not None and origin != routing_settings.frontend_origin:
                return JSONResponse(status_code=403, content={"detail": "Untrusted request origin"})
        return await call_next(request)
    application.add_api_route("/health", health_check, methods=["GET"])
    application.include_router(api_router, prefix=routing_settings.api_prefix)

    @application.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI's default errors echo inputs, which may contain login passwords.
        errors = [
            {key: error[key] for key in ("loc", "msg", "type")}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    return application


app = create_app()
