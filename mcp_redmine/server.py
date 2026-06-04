import os, yaml, pathlib, json, uuid, base64
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

# Cache of verified Redmine users (oauth_user -> resolved_login or None)
_verified_users_cache: dict[str, str | None] = {}

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
def _user_exists_in_redmine(login_or_email: str) -> str | None:
    """Check if user exists in Redmine by login or email. Results are cached.
    
    Args:
        login_or_email: Username or email to search for
        
    Returns:
        The Redmine login if found (exactly one match), None otherwise.
        If searching by email and multiple users share the same email, returns None.
    """
    if login_or_email in _verified_users_cache:
        return _verified_users_cache[login_or_email]
    
    try:
        # Search by name (matches login, firstname, lastname, and email)
        url = urljoin(REDMINE_URL, f'users.json?name={login_or_email}&limit=100')
        response = httpx.get(url, headers={'X-Redmine-API-Key': REDMINE_API_KEY},
                            timeout=10.0, verify=not REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS)
        if response.status_code == 200:
            users = response.json().get('users', [])
            
            # First, try exact login match
            for user in users:
                if user.get('login') == login_or_email:
                    _verified_users_cache[login_or_email] = user.get('login')
                    return user.get('login')
            
            # If no login match, try exact email match
            email_matches = [u for u in users if u.get('mail') == login_or_email]
            if len(email_matches) == 1:
                resolved_login = email_matches[0].get('login')
                get_logger(__name__).info(f"User '{login_or_email}' matched by email to Redmine user '{resolved_login}'")
                _verified_users_cache[login_or_email] = resolved_login
                return resolved_login
            elif len(email_matches) > 1:
                get_logger(__name__).warning(f"Email '{login_or_email}' matches multiple Redmine users, skipping impersonation")
                _verified_users_cache[login_or_email] = None
                return None
            
            get_logger(__name__).warning(f"User '{login_or_email}' from OAuth not found in Redmine, skipping impersonation")
    except Exception as e:
        get_logger(__name__).error(f"Failed to verify user '{login_or_email}' in Redmine: {e}")
    
    _verified_users_cache[login_or_email] = None
    return None

def request(path: str, method: str = 'get', data: dict = None, params: dict = None,
            content_type: str = 'application/json', content: bytes = None) -> dict:
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': content_type,
        **REDMINE_HEADERS
    }
    # Impersonate the OAuth-authenticated user (requires admin API key in Redmine)
    # Only add header if user exists in Redmine, otherwise skip silently
    oauth_user = current_user_var.get()
    if oauth_user:
        resolved_login = _user_exists_in_redmine(oauth_user)
        if resolved_login:
            headers['X-Redmine-Switch-User'] = resolved_login
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


### Direct Download Endpoint ###

async def attachment_download(request: Request) -> Response:
    """
    Direct download endpoint for Redmine attachments.
    
    URL: /attachments/{attachment_id}/download
    
    Authentication:
    - If OAUTH_ENABLED: requires Bearer token in Authorization header
    - Otherwise: uses the server's REDMINE_API_KEY directly
    
    The impersonation header is added if the OAuth user exists in Redmine.
    """
    attachment_id = request.path_params.get("attachment_id")
    if not attachment_id:
        return JSONResponse({"error": "attachment_id required"}, status_code=400)
    
    try:
        attachment_id = int(attachment_id)
    except ValueError:
        return JSONResponse({"error": "attachment_id must be an integer"}, status_code=400)
    
    # Build headers for Redmine request
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        **REDMINE_HEADERS
    }
    
    # Add impersonation header if OAuth user is set and exists in Redmine
    oauth_user = current_user_var.get()
    if oauth_user:
        resolved_login = _user_exists_in_redmine(oauth_user)
        if resolved_login:
            headers['X-Redmine-Switch-User'] = resolved_login
    
    try:
        # First get attachment metadata
        meta_url = urljoin(REDMINE_URL, f'attachments/{attachment_id}.json')
        async with httpx.AsyncClient(timeout=30.0, verify=not REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS) as client:
            meta_response = await client.get(meta_url, headers=headers)
            
            if meta_response.status_code == 404:
                return JSONResponse({"error": "Attachment not found"}, status_code=404)
            if meta_response.status_code == 403:
                return JSONResponse({"error": "Access denied"}, status_code=403)
            if meta_response.status_code != 200:
                return JSONResponse({"error": f"Redmine error: {meta_response.status_code}"}, status_code=meta_response.status_code)
            
            attachment = meta_response.json().get("attachment", {})
            filename = attachment.get("filename", f"attachment_{attachment_id}")
            content_type = attachment.get("content_type", "application/octet-stream")
            
            # Download the actual file
            download_url = urljoin(REDMINE_URL, f'attachments/download/{attachment_id}/{filename}')
            file_response = await client.get(download_url, headers=headers)
            
            if file_response.status_code != 200:
                return JSONResponse({"error": f"Download failed: {file_response.status_code}"}, status_code=file_response.status_code)
            
            # Return file with proper headers for browser download
            return Response(
                content=file_response.content,
                media_type=content_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Length": str(len(file_response.content)),
                }
            )
    except httpx.TimeoutException:
        return JSONResponse({"error": "Request timeout"}, status_code=504)
    except Exception as e:
        get_logger(__name__).error(f"Download error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# Tools - Disable DNS rebinding protection for public deployment
mcp = FastMCP(
    "Redmine MCP server",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
)
get_logger(__name__).info(f"Starting MCP Redmine version {VERSION}")

@mcp.tool(description="""
Execute a direct request to the Redmine REST API.

This is the main tool for interacting with Redmine. Use it to create, read, update, 
or delete any Redmine resource (issues, projects, users, time entries, etc.).

Args:
    path: API endpoint path (e.g. '/issues.json', '/projects/myproject/issues.json')
    method: HTTP method - 'get', 'post', 'put', 'patch', or 'delete' (default: 'get')
    data: Request body as dictionary. Used for POST/PUT/PATCH to create or update resources.
          Example for creating issue: {{'issue': {{'project_id': 1, 'subject': 'Bug title'}}}}
    params: Query parameters as dictionary. Used for filtering, pagination, includes.
          Example: {{'status_id': 'open', 'limit': 25, 'include': 'attachments,journals'}}

Returns:
    str: Response with status_code, body (JSON data from Redmine), and error message if any.

Common endpoints:
    - GET /issues.json - List issues
    - GET /issues/{{id}}.json - Get single issue
    - POST /issues.json - Create issue
    - PUT /issues/{{id}}.json - Update issue
    - GET /projects.json - List projects
    - GET /users/current.json - Get current user info

{}""".format(REDMINE_REQUEST_INSTRUCTIONS).strip())
    
def redmine_request(path: str, method: str = 'get', data: dict = None, params: dict = None) -> str:
    return wrap_insecure_content(format_response(request(path, method=method, data=data, params=params)))

@mcp.tool()
def redmine_paths_list() -> str:
    """
    List all available Redmine API endpoints from the OpenAPI specification.
    
    Use this tool to discover what API endpoints are available. Once you find a relevant 
    endpoint, use redmine_paths_info to get detailed documentation about parameters, 
    request body format, and response structure.
    
    Returns:
        str: List of API path templates (e.g. '/issues.json', '/projects/{project_id}/memberships.json')
    
    Example workflow:
        1. Call redmine_paths_list() to see available endpoints
        2. Call redmine_paths_info(['/issues.json']) to get details
        3. Call redmine_request('/issues.json', 'get', params={'status_id': 'open'}) to execute
    """
    return format_response(list(SPEC['paths'].keys()))

@mcp.tool()
def redmine_paths_info(path_templates: list) -> str:
    """
    Get detailed OpenAPI documentation for specific Redmine API endpoints.
    
    Returns complete specification including HTTP methods, parameters, request body 
    schema, and response format for each requested endpoint.
    
    Args:
        path_templates: List of endpoint paths to get info for.
                       Example: ['/issues.json', '/time_entries.json']
        
    Returns:
        str: Full API specification for each path including:
             - Supported HTTP methods (GET, POST, PUT, DELETE)
             - Query parameters and their types
             - Request body schema for POST/PUT
             - Response body schema
    
    Example:
        redmine_paths_info(['/issues/{issue_id}.json']) 
        -> Returns how to get, update, or delete an issue
    """
    info = {}
    for path in path_templates:
        if path in SPEC['paths']:
            info[path] = SPEC['paths'][path]

    return format_response(info)

@mcp.tool()
def redmine_upload(file_path: str, description: str = None) -> str:
    """
    Upload a file from the server filesystem to Redmine (for server-side automation).
    
    NOTE: This tool requires REDMINE_ALLOWED_DIRECTORIES to be configured and only works 
    with files on the MCP server's filesystem. For uploading from Claude, use 
    redmine_attachment_add() which accepts base64 content instead.

    Args:
        file_path: Absolute path to file on server (must be within REDMINE_ALLOWED_DIRECTORIES)
        description: Optional description for the attachment

    Returns:
        str: Upload token in body.upload.token - use this to attach to an issue:
             redmine_request('/issues/{id}.json', 'put', 
                {'issue': {'uploads': [{'token': '<token>', 'filename': '<name>'}]}})
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
    Download an attachment from Redmine to the server filesystem (for server-side automation).
    
    NOTE: This tool saves files to the MCP server's filesystem. For getting file content 
    directly in Claude, use redmine_attachment_get() which returns base64 content instead.

    Args:
        attachment_id: The ID of the attachment (get this from redmine_issue_attachments)
        save_path: Absolute path on server where to save (must be within REDMINE_ALLOWED_DIRECTORIES)
        filename: Optional custom filename. If not provided, uses original filename from Redmine.

    Returns:
        str: saved_to path and filename on success, or error message if failed.
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

@mcp.tool()
def redmine_issue_attachments(issue_id: int) -> str:
    """
    List all attachments for a Redmine issue.
    
    Use this to discover what files are attached to an issue before downloading them.

    Args:
        issue_id: The Redmine issue ID (the number, e.g. 1234)

    Returns:
        str: List of attachments, each containing:
             - id: Attachment ID (use this with redmine_attachment_get to download)
             - filename: Original filename
             - filesize: Size in bytes
             - content_type: MIME type (e.g. 'application/pdf', 'image/png')
             - description: User-provided description
             - author: Who uploaded the file
             - created_on: Upload timestamp
             - download_url: Direct download URL (requires OAuth token if enabled)
    
    Example workflow:
        1. redmine_issue_attachments(1234) -> get list with attachment IDs
        2. redmine_attachment_get(5678) -> download specific attachment as base64
        
    Or use the download_url directly in a browser (with OAuth authentication if enabled).
    """
    try:
        response = request(f"issues/{issue_id}.json?include=attachments", "get")
        if response["status_code"] != 200:
            return format_response(response)

        attachments = response["body"].get("issue", {}).get("attachments", [])
        
        # Add download URLs for each attachment
        for att in attachments:
            att["download_url"] = f"{MCP_SERVER_URL}/attachments/{att['id']}/download"
            # Direct Redmine URL with API key (works without OAuth, for Claude Desktop)
            att["direct_download_url"] = f"{REDMINE_URL}attachments/download/{att['id']}/{att['filename']}?key={REDMINE_API_KEY}"
        
        return format_response({
            "status_code": 200,
            "body": {"attachments": attachments},
            "error": ""
        })
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

@mcp.tool()
def redmine_attachment_get(attachment_id: int) -> str:
    """
    Download an attachment from Redmine and return its content as base64.
    
    This is the recommended way to get file contents in Claude - the base64 data 
    IS the complete original file, just encoded for text transmission.

    Args:
        attachment_id: The attachment ID (get this from redmine_issue_attachments)

    Returns:
        str: Attachment with:
             - filename: Original filename
             - content_type: MIME type to know how to handle the content
             - size: File size in bytes
             - content_base64: The complete file encoded in base64
        
    How to use the content_base64:
        - Text files (txt, csv, json, xml, md): Decode to read the text directly
        - Images (png, jpg, gif): Can be displayed or analyzed visually
        - PDFs: Decode to extract text content
        - Binary files: Decode to get original bytes
        
        To decode in Python: base64.b64decode(content_base64)
        
    Example:
        1. redmine_issue_attachments(1234) -> find attachment ID 5678
        2. redmine_attachment_get(5678) -> get the file content
        3. Process the content_base64 based on content_type
    """
    try:
        # Get attachment metadata
        attachment_response = request(f"attachments/{attachment_id}.json", "get")
        if attachment_response["status_code"] != 200:
            return format_response(attachment_response)

        attachment = attachment_response["body"]["attachment"]
        filename = attachment["filename"]
        content_type = attachment.get("content_type", "application/octet-stream")
        filesize = attachment.get("filesize", 0)

        # Download the file content
        response = request(f"attachments/download/{attachment_id}/{filename}", "get",
                           content_type="application/octet-stream")
        if response["status_code"] != 200 or not response["body"]:
            return format_response(response)

        # Encode content as base64
        content_base64 = base64.b64encode(response["body"]).decode('ascii')

        return format_response({
            "status_code": 200,
            "body": {
                "filename": filename,
                "content_type": content_type,
                "size": filesize,
                "content_base64": content_base64,
                "download_url": f"{MCP_SERVER_URL}/attachments/{attachment_id}/download",
                "direct_download_url": f"{REDMINE_URL}attachments/download/{attachment_id}/{filename}?key={REDMINE_API_KEY}"
            },
            "error": ""
        })
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

@mcp.tool()
def redmine_attachment_add(filename: str, content_base64: str, description: str = None) -> str:
    """
    Upload a file to Redmine using base64 content (works directly from Claude).
    
    This is the recommended way to upload files from Claude. The file content must be 
    provided as base64 - this is how binary data is transmitted over text protocols.

    Args:
        filename: Name for the file in Redmine (e.g. 'report.pdf', 'data.csv')
        content_base64: The file content encoded in base64
        description: Optional description shown in Redmine

    Returns:
        str: Upload response containing a token in body.upload.token
        
    After uploading, attach the file to an issue (two-step process):
        1. Upload: redmine_attachment_add('report.pdf', '<base64>') -> get token
        2. Attach: redmine_request('/issues/123.json', 'put', {
               'issue': {'uploads': [{'token': '<token>', 'filename': 'report.pdf'}]}
           })
    
    To create base64 from text: base64.b64encode(text.encode()).decode()
    To create base64 from bytes: base64.b64encode(bytes_data).decode()
    """
    try:
        file_content = base64.b64decode(content_base64)
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"Invalid base64 content: {e}"})

    try:
        params = {'filename': filename}
        if description:
            params['description'] = description

        result = request(path='uploads.json', method='post', params=params,
                         content_type='application/octet-stream', content=file_content)
        return format_response(result)
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

@mcp.tool()
def redmine_whoami() -> str:
    """
    Show current authentication status and user information.
    
    Use this to verify:
    - If OAuth2 authentication is enabled
    - Which user is making requests to Redmine (OAuth user or generic API key)
    - If the OAuth user exists in Redmine and impersonation is active

    Returns:
        str: Authentication details including:
             - oauth_enabled: Whether OAuth2 is configured
             - oauth_user: Username/email from OAuth2 token (if authenticated)
             - oauth_user_exists_in_redmine: Whether the OAuth user was found in Redmine (by login or email)
             - resolved_redmine_login: The Redmine login resolved from oauth_user (may differ if matched by email)
             - impersonation_active: True if using X-Redmine-Switch-User header
             - redmine_user: The actual user making requests to Redmine
             - redmine_api_user: User info from Redmine API (who the API key belongs to)
    
    If impersonation_active is False, all actions are recorded as the API key owner,
    not the OAuth user. This happens when:
    - OAuth is disabled
    - OAuth user doesn't exist in Redmine
    - API key doesn't have admin privileges
    """
    try:
        oauth_user = current_user_var.get()
        resolved_login = _user_exists_in_redmine(oauth_user) if oauth_user else None
        
        # Get the Redmine API key user
        redmine_response = request("users/current.json", "get")
        redmine_api_user = None
        if redmine_response["status_code"] == 200:
            redmine_api_user = redmine_response["body"].get("user", {})
        
        impersonation_active = bool(oauth_user and resolved_login)
        
        return format_response({
            "status_code": 200,
            "body": {
                "oauth_enabled": OAUTH_ENABLED,
                "oauth_user": oauth_user,
                "oauth_user_exists_in_redmine": resolved_login is not None,
                "resolved_redmine_login": resolved_login,
                "impersonation_active": impersonation_active,
                "redmine_user": resolved_login if impersonation_active else (redmine_api_user.get("login") if redmine_api_user else "unknown"),
                "redmine_api_user": {
                    "id": redmine_api_user.get("id"),
                    "login": redmine_api_user.get("login"),
                    "firstname": redmine_api_user.get("firstname"),
                    "lastname": redmine_api_user.get("lastname"),
                    "admin": redmine_api_user.get("admin"),
                } if redmine_api_user else None
            },
            "error": ""
        })
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
            Route("/attachments/{attachment_id:int}/download", attachment_download, methods=["GET"]),
        ]
        for route in reversed(oauth_routes):
            app.routes.insert(0, route)

        uvicorn.run(app, host=args.host, port=args.port)
    else:
        mcp.run(transport=args.transport)

if __name__ == "__main__":
    main()
