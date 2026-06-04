import os, yaml, pathlib, json, uuid
from urllib.parse import urljoin
from typing import Optional

import time
import contextvars
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient
from starlette.responses import JSONResponse, Response, RedirectResponse
from starlette.requests import Request
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.logging import get_logger
from mcp.server.transport_security import TransportSecuritySettings

### Constants ###

VERSION = "2026.01.13.152335"

# Load OpenAPI spec
current_dir = pathlib.Path(__file__).parent
with open(current_dir / 'redmine_openapi.yml') as f:
    SPEC = yaml.safe_load(f)

# Constants from environment
REDMINE_URL = os.environ['REDMINE_URL'].rstrip('/') + '/'  # Normalize to always end with /
REDMINE_API_KEY = os.environ['REDMINE_API_KEY']
REDMINE_RESPONSE_FORMAT = os.environ.get('REDMINE_RESPONSE_FORMAT', 'yaml').lower()

# OAuth Configuration
OAUTH_ENABLED = os.environ.get('OAUTH_ENABLED', 'false').lower() == 'true'
OAUTH_ISSUER_URL = os.environ.get('OAUTH_ISSUER_URL', 'https://auth.m-risk.com/auth/realms/mrisk')
OAUTH_JWKS_URL = f"{OAUTH_ISSUER_URL}/protocol/openid-connect/certs"
MCP_SERVER_URL = os.environ.get('MCP_SERVER_URL', 'https://redmine-mcp.m-risk.com').rstrip('/')

# OAuth client credentials (static client pre-registered in Keycloak)
OAUTH_CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID', 'redmine-mcp')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', '')

# Keycloak endpoints derived from issuer
KC_AUTHORIZE_URL = f"{OAUTH_ISSUER_URL}/protocol/openid-connect/auth"
KC_TOKEN_URL = f"{OAUTH_ISSUER_URL}/protocol/openid-connect/token"

# Holds the authenticated user's login for the duration of a request (impersonation)
current_user_var = contextvars.ContextVar("current_user", default=None)

# Cache of verified Redmine users (login -> exists)
_verified_users_cache: dict[str, bool] = {}

# Custom headers (format: "Header1: Value1, Header2: Value2")
REDMINE_HEADERS = {}
if custom_headers := os.environ.get('REDMINE_HEADERS', ''):
    for header in custom_headers.split(','):
        if ':' in header:
            key, value = header.split(':', 1)
            REDMINE_HEADERS[key.strip()] = value.strip()

# Allowed directories for upload/download (secure by default - disabled if not set)
REDMINE_ALLOWED_DIRECTORIES = [
    pathlib.Path(d.strip()).resolve()
    for d in os.environ.get('REDMINE_ALLOWED_DIRECTORIES', '').split(',')
    if d.strip()
]

# SSL verification (disabled only when explicitly set to "1")
REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS = os.environ.get('REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS') == '1'

if "REDMINE_REQUEST_INSTRUCTIONS" in os.environ:
    with open(os.environ["REDMINE_REQUEST_INSTRUCTIONS"]) as f:
        REDMINE_REQUEST_INSTRUCTIONS = f.read()
else:
    REDMINE_REQUEST_INSTRUCTIONS = ""


# Core
def _user_exists_in_redmine(login: str) -> bool:
    """Check if user exists in Redmine. Results are cached."""
    if login in _verified_users_cache:
        return _verified_users_cache[login]
    
    try:
        url = urljoin(REDMINE_URL, f'users.json?name={login}&limit=100')
        response = httpx.get(url, headers={'X-Redmine-API-Key': REDMINE_API_KEY},
                            timeout=10.0, verify=not REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS)
        if response.status_code == 200:
            users = response.json().get('users', [])
            exists = any(u.get('login') == login for u in users)
            _verified_users_cache[login] = exists
            if not exists:
                get_logger(__name__).warning(f"User '{login}' from OAuth not found in Redmine, skipping impersonation")
            return exists
    except Exception as e:
        get_logger(__name__).error(f"Failed to verify user '{login}' in Redmine: {e}")
    
    _verified_users_cache[login] = False
    return False

def request(path: str, method: str = 'get', data: dict = None, params: dict = None,
            content_type: str = 'application/json', content: bytes = None) -> dict:
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': content_type,
        **REDMINE_HEADERS
    }
    # Impersonate the OAuth-authenticated user (requires admin API key in Redmine)
    # Only add header if user exists in Redmine, otherwise skip silently
    switch_user = current_user_var.get()
    if switch_user and _user_exists_in_redmine(switch_user):
        headers['X-Redmine-Switch-User'] = switch_user
    url = urljoin(REDMINE_URL, path.lstrip('/'))

    try:
        response = httpx.request(method=method.lower(), url=url, json=data, params=params, headers=headers,
                                 content=content, timeout=60.0, verify=not REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS)
        response.raise_for_status()

        body = None
        if response.content:
            try:
                body = response.json()
            except ValueError:
                body = response.content

        return {"status_code": response.status_code, "body": body, "error": ""}
    except Exception as e:
        try:
            status_code = e.response.status_code
        except:
            status_code = 0

        try:
            body = e.response.json()
        except:
            try:
                body = e.response.text
            except:
                body = None

        return {"status_code": status_code, "body": body, "error": f"{e.__class__.__name__}: {e}"}
        
def format_response(obj):
    """Format response as YAML or JSON based on REDMINE_RESPONSE_FORMAT env var."""
    if REDMINE_RESPONSE_FORMAT == 'json':
        return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    # YAML: Allow direct Unicode output, prevent line wrapping for long lines, and avoid automatic key sorting.
    return yaml.safe_dump(obj, allow_unicode=True, sort_keys=False, width=4096)


def wrap_insecure_content(content: str) -> str:
    """Wrap content that may contain user-generated data with security tags to prevent prompt injection."""
    tag_id = uuid.uuid4().hex[:16]
    return f"<insecure-content-{tag_id}>\n{content}\n</insecure-content-{tag_id}>"


def validate_path(file_path: str, must_exist: bool = True) -> tuple[str | None, pathlib.Path | None]:
    """
    Validate and resolve a file path.
    Returns (None, resolved_path) on success, (error_message, None) on failure.
    """
    # Require allowed directories to be configured (secure by default)
    if not REDMINE_ALLOWED_DIRECTORIES:
        return "File operations disabled: REDMINE_ALLOWED_DIRECTORIES not configured", None

    try:
        path = pathlib.Path(file_path).expanduser().resolve()
    except Exception as e:
        return f"Invalid path: {file_path} ({e})", None

    if not path.is_absolute():
        return f"Path must be absolute, got: {file_path}", None

    # Check path is within allowed directories
    if not any(path.is_relative_to(allowed) for allowed in REDMINE_ALLOWED_DIRECTORIES):
        return f"Path not in allowed directories: {file_path}", None

    if must_exist and not path.exists():
        return f"File not found: {path}", None

    return None, path


### OAuth Implementation ###

class OAuthMiddleware:
    """Pure ASGI middleware to validate OAuth tokens (MCP authorization spec).

    Implemented as raw ASGI (not BaseHTTPMiddleware) so it does not buffer
    streaming SSE responses and so contextvars propagate to tool execution.
    """

    def __init__(self, app):
        self.app = app
        self.jwks_client = PyJWKClient(OAUTH_JWKS_URL) if OAUTH_ENABLED else None
        if OAUTH_ENABLED:
            get_logger(__name__).info(f"OAuth enabled with issuer: {OAUTH_ISSUER_URL}")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        public_paths = ("/.well-known/", "/authorize", "/token", "/register")
        if not OAUTH_ENABLED or any(path.startswith(p) for p in public_paths):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization", b"").decode()
        if not auth_header.startswith("Bearer "):
            await self._send_unauthorized(send)
            return

        token = auth_header[7:]
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            decoded = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=OAUTH_ISSUER_URL,
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            await self._send_unauthorized(send, error="Token expired")
            return
        except jwt.InvalidTokenError as e:
            await self._send_unauthorized(send, error=f"Invalid token: {e}")
            return
        except Exception as e:
            get_logger(__name__).error(f"OAuth validation error: {e}")
            await self._send_unauthorized(send, error="Authentication failed")
            return

        # Set the impersonation user for the duration of this request
        username = decoded.get("preferred_username") or decoded.get("email")
        ctx_token = current_user_var.set(username)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user_var.reset(ctx_token)

    async def _send_unauthorized(self, send, error: str = None):
        """Send a 401 with WWW-Authenticate header per MCP spec."""
        resource_metadata_url = f"{MCP_SERVER_URL}/.well-known/oauth-protected-resource"
        body = json.dumps({
            "error": "unauthorized",
            "error_description": error or "Authentication required",
        }).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", f'Bearer resource_metadata="{resource_metadata_url}"'.encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})


### OAuth Proxy Endpoints (bridge Claude.ai DCR flow to Keycloak static client) ###

async def oauth_protected_resource(request: Request) -> Response:
    """RFC 9728 protected resource metadata. Points to this server as the authorization server."""
    return JSONResponse({
        "resource": MCP_SERVER_URL,
        "authorization_servers": [MCP_SERVER_URL],
    })


async def oauth_authorization_server(request: Request) -> Response:
    """RFC 8414 authorization server metadata advertising this server's proxy endpoints."""
    return JSONResponse({
        "issuer": MCP_SERVER_URL,
        "authorization_endpoint": f"{MCP_SERVER_URL}/authorize",
        "token_endpoint": f"{MCP_SERVER_URL}/token",
        "registration_endpoint": f"{MCP_SERVER_URL}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["openid", "email", "profile", "offline_access"],
    })


async def oauth_register(request: Request) -> Response:
    """RFC 7591 Dynamic Client Registration. Returns the static Keycloak client_id."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    redirect_uris = body.get("redirect_uris", [])
    return JSONResponse(status_code=201, content={
        "client_id": OAUTH_CLIENT_ID,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })


async def oauth_authorize(request: Request) -> Response:
    """Redirect the user to Keycloak's authorize endpoint, forcing our static client_id."""
    params = dict(request.query_params)
    params["client_id"] = OAUTH_CLIENT_ID
    if "scope" not in params or "openid" not in params.get("scope", ""):
        params["scope"] = (params.get("scope", "") + " openid").strip()
    return RedirectResponse(url=f"{KC_AUTHORIZE_URL}?{urlencode(params)}")


async def oauth_token(request: Request) -> Response:
    """Proxy the token exchange to Keycloak, injecting the confidential client_secret."""
    form = dict(await request.form())
    form["client_id"] = OAUTH_CLIENT_ID
    if OAUTH_CLIENT_SECRET:
        form["client_secret"] = OAUTH_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=30.0) as client:
        kc_response = await client.post(
            KC_TOKEN_URL,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    try:
        content = kc_response.json()
    except Exception:
        content = {"error": "invalid_response", "error_description": kc_response.text}

    return JSONResponse(status_code=kc_response.status_code, content=content)


# Tools - Disable DNS rebinding protection for public deployment
mcp = FastMCP(
    "Redmine MCP server",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
)
get_logger(__name__).info(f"Starting MCP Redmine version {VERSION}")

@mcp.tool(description="""
Make a request to the Redmine API

Args:
    path: API endpoint path (e.g. '/issues.json')
    method: HTTP method to use (default: 'get')
    data: Dictionary for request body (for POST/PUT)
    params: Dictionary for query parameters

Returns:
    str: YAML string containing response status code, body and error message

{}""".format(REDMINE_REQUEST_INSTRUCTIONS).strip())
    
def redmine_request(path: str, method: str = 'get', data: dict = None, params: dict = None) -> str:
    return wrap_insecure_content(format_response(request(path, method=method, data=data, params=params)))

@mcp.tool()
def redmine_paths_list() -> str:
    """Return a list of available API paths from OpenAPI spec
    
    Retrieves all endpoint paths defined in the Redmine OpenAPI specification. Remember that you can use the
    redmine_paths_info tool to get the full specfication for a path.
    
    Returns:
        str: YAML string containing a list of path templates (e.g. '/issues.json')
    """
    return format_response(list(SPEC['paths'].keys()))

@mcp.tool()
def redmine_paths_info(path_templates: list) -> str:
    """Get full path information for given path templates
    
    Args:
        path_templates: List of path templates (e.g. ['/issues.json', '/projects.json'])
        
    Returns:
        str: YAML string containing API specifications for the requested paths
    """
    info = {}
    for path in path_templates:
        if path in SPEC['paths']:
            info[path] = SPEC['paths'][path]

    return format_response(info)

@mcp.tool()
def redmine_upload(file_path: str, description: str = None) -> str:
    """
    Upload a file to Redmine and get a token for attachment

    Args:
        file_path: Fully qualified path to the file to upload (must be within REDMINE_ALLOWED_DIRECTORIES)
        description: Optional description for the file

    Returns:
        str: YAML string containing response status code, body and error message
             The body contains the attachment token
    """
    error, path = validate_path(file_path, must_exist=True)
    if error:
        return format_response({"status_code": 0, "body": None, "error": error})

    try:
        params = {'filename': path.name}
        if description:
            params['description'] = description

        with open(path, 'rb') as f:
            file_content = f.read()

        result = request(path='uploads.json', method='post', params=params,
                         content_type='application/octet-stream', content=file_content)
        return format_response(result)
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

@mcp.tool()
def redmine_download(attachment_id: int, save_path: str, filename: str = None) -> str:
    """
    Download an attachment from Redmine and save it to a local file

    Args:
        attachment_id: The ID of the attachment to download
        save_path: Fully qualified path where the file should be saved to (must be within REDMINE_ALLOWED_DIRECTORIES)
        filename: Optional filename to use for the attachment. If not provided,
                 will be determined from attachment data or URL

    Returns:
        str: YAML string containing download status, file path, and any error messages
    """
    error, path = validate_path(save_path, must_exist=False)
    if error:
        return format_response({"status_code": 0, "body": None, "error": error})

    if path.is_dir():
        return format_response({"status_code": 0, "body": None, "error": f"Path can't be a directory: {save_path}"})

    try:
        if not filename:
            attachment_response = request(f"attachments/{attachment_id}.json", "get")
            if attachment_response["status_code"] != 200:
                return format_response(attachment_response)

            filename = attachment_response["body"]["attachment"]["filename"]

        response = request(f"attachments/download/{attachment_id}/{filename}", "get",
                           content_type="application/octet-stream")
        if response["status_code"] != 200 or not response["body"]:
            return format_response(response)

        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'wb') as f:
            f.write(response["body"])

        return format_response({"status_code": 200, "body": {"saved_to": str(path), "filename": filename}, "error": ""})
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

def main():
    """Main entry point for the mcp-redmine package."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Redmine Server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio",
                        help="Transport type (default: stdio)")
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP transport (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP transport (default: 8000)")
    args = parser.parse_args()

    if args.transport in ["sse", "streamable-http"]:
        import uvicorn
        from starlette.routing import Route

        mcp.settings.host = args.host
        mcp.settings.port = args.port

        # Get the Starlette app from FastMCP
        if args.transport == "sse":
            app = mcp.sse_app()
        else:
            app = mcp.streamable_http_app()

        # Add OAuth middleware
        app.add_middleware(OAuthMiddleware)

        # Register OAuth discovery + proxy routes at the beginning
        oauth_routes = [
            Route("/.well-known/oauth-protected-resource", oauth_protected_resource),
            Route("/.well-known/oauth-authorization-server", oauth_authorization_server),
            Route("/.well-known/openid-configuration", oauth_authorization_server),
            Route("/register", oauth_register, methods=["POST"]),
            Route("/authorize", oauth_authorize, methods=["GET"]),
            Route("/token", oauth_token, methods=["POST"]),
        ]
        for route in reversed(oauth_routes):
            app.routes.insert(0, route)

        uvicorn.run(app, host=args.host, port=args.port)
    else:
        mcp.run(transport=args.transport)

if __name__ == "__main__":
    main()
