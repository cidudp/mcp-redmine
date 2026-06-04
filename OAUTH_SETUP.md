# Configuración OAuth para MCP Redmine con Keycloak

## Paso 1: Crear cliente en Keycloak

1. Accede a Keycloak Admin Console: `https://auth.m-risk.com/auth/admin/`
2. Selecciona el realm: `mrisk`
3. Ve a **Clients** → **Create**
4. Configura:
   - **Client ID**: `redmine-mcp`
   - **Client Protocol**: `openid-connect`
   - **Access Type**: `confidential`
   - **Standard Flow Enabled**: `ON`
   - **Direct Access Grants Enabled**: `OFF`
   - **Valid Redirect URIs**: 
     - `https://redmine-mcp.m-risk.com/oauth2/callback`
     - `https://claude.ai/*`
   - **Web Origins**: `https://claude.ai`
   - **Base URL**: `https://redmine-mcp.m-risk.com`

5. Guarda y ve a la pestaña **Credentials**
6. Copia el **Secret** generado

## Paso 2: Configurar variables de entorno

```bash
# Copia el ejemplo
cp .env.oauth.example .env.oauth

# Genera cookie secret
openssl rand -base64 32

# Edita .env.oauth con:
# - REDMINE_URL: URL de tu Redmine
# - REDMINE_API_KEY: Tu API key de Redmine
# - OAUTH2_CLIENT_SECRET: El secret de Keycloak
# - OAUTH2_COOKIE_SECRET: El generado con openssl
```

## Paso 3: Desplegar con OAuth

```bash
docker-compose -f docker-compose-oauth.yml --env-file .env.oauth up -d
```

## Paso 4: Verificar

```bash
# Ver logs
docker logs -f oauth2-proxy

# Probar endpoint
curl -I https://redmine-mcp.m-risk.com/sse
# Debería redirigir a Keycloak (302)
```

## Paso 5: Configurar en claude.ai

1. Ve a Settings → Connectors
2. Click "Add custom connector"
3. Configura:
   - **URL**: `https://redmine-mcp.m-risk.com/sse`
   - **Name**: `redmine`
   - **OAuth Client ID**: `redmine-mcp`
   - **OAuth Client Secret**: (el de Keycloak)

## Endpoints importantes

- **Issuer**: `https://auth.m-risk.com/auth/realms/mrisk`
- **Authorization**: `https://auth.m-risk.com/auth/realms/mrisk/protocol/openid-connect/auth`
- **Token**: `https://auth.m-risk.com/auth/realms/mrisk/protocol/openid-connect/token`
- **UserInfo**: `https://auth.m-risk.com/auth/realms/mrisk/protocol/openid-connect/userinfo`

## Troubleshooting

### Error: "Invalid redirect_uri"
Verifica que `https://redmine-mcp.m-risk.com/oauth2/callback` esté en Valid Redirect URIs

### Error: "Unauthorized"
Verifica que el Client Secret sea correcto en `.env.oauth`

### Error: "Cookie secret must be 32 bytes"
Genera uno nuevo: `openssl rand -base64 32`
