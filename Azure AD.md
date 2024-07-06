Azure Active Directory (Azure AD) provides robust authentication and authorization capabilities for applications, including Angular frontend applications and .NET Core backend APIs. Integrating Azure AD authentication involves configuring both the frontend and backend to leverage Azure AD's identity services. Here's how you can implement Azure AD authentication with Angular and .NET Core:

### Angular Frontend Integration

#### 1. Configure Azure AD App Registration

1. **Register the Application**:
   - Go to the Azure portal (https://portal.azure.com) and navigate to Azure Active Directory.
   - Register a new application to get a `Client ID` and `Tenant ID`. Configure the redirect URI as `http://localhost:4200` (for local development).

2. **Configure Authentication**:
   - Enable ID tokens and Access tokens in the Authentication settings of your Azure AD App registration.

#### 2. Install Required Packages

Install MSAL (Microsoft Authentication Library) for Angular to handle authentication with Azure AD:

```bash
npm install @azure/msal-angular
```

#### 3. Implement Authentication Service

Create an authentication service (`auth.service.ts`) to handle login, logout, and token acquisition:

```typescript
import { Injectable } from '@angular/core';
import { PublicClientApplication, InteractionType } from '@azure/msal-browser';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private msalConfig = {
    auth: {
      clientId: 'your_client_id',
      authority: 'https://login.microsoftonline.com/your_tenant_id',
      redirectUri: 'http://localhost:4200',
    }
  };

  private pca = new PublicClientApplication(this.msalConfig);

  constructor() { }

  login() {
    const request = {
      scopes: ['openid', 'profile', 'user.read']
    };
    this.pca.loginPopup(request)
      .then(response => {
        console.log('Login success:', response);
        // Handle successful login (e.g., store tokens)
      })
      .catch(error => {
        console.error('Login error:', error);
        // Handle login failure
      });
  }

  logout() {
    this.pca.logout();
  }

  getToken() {
    return this.pca.getTokenSilent({ scopes: ['openid', 'profile', 'user.read'] });
  }

}
```

#### 4. Secure API Requests

Use the acquired token to secure API requests:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class ApiService {

  private apiEndpoint = 'https://your-api.azurewebsites.net/api/data';

  constructor(private http: HttpClient, private authService: AuthService) { }

  getData() {
    return this.authService.getToken().then(token => {
      const headers = new HttpHeaders({
        'Authorization': `Bearer ${token.accessToken}`
      });
      return this.http.get(this.apiEndpoint, { headers }).toPromise();
    });
  }

}
```

### .NET Core Backend Integration

#### 1. Configure Azure AD App Registration

1. **Register the Application**:
   - Register a new application in Azure AD to get a `Client ID` and `Tenant ID`.

2. **API Permissions**:
   - Grant API permissions for Microsoft Graph or other APIs your backend needs to access.

#### 2. Configure ASP.NET Core Application

1. **Install Packages**:

   Install the Microsoft.Identity.Web package for ASP.NET Core integration with Azure AD:

   ```bash
   dotnet add package Microsoft.Identity.Web
   ```

2. **Configure Authentication**:

   Configure Azure AD authentication in `Startup.cs`:

   ```csharp
   services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
       .AddMicrosoftIdentityWebApi(options =>
       {
           Configuration.Bind("AzureAd", options);
       });
   ```

3. **Secure API Endpoints**:

   Use `[Authorize]` attribute to secure API endpoints:

   ```csharp
   [ApiController]
   [Route("api/data")]
   public class DataController : ControllerBase
   {
       [HttpGet]
       [Authorize]
       public IActionResult Get()
       {
           // Access user claims
           var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
           // Return protected data
           return Ok(new { message = "Protected data accessed successfully", userId });
       }
   }
   ```

#### 3. Configuration

Configure Azure AD settings in `appsettings.json`:

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "Domain": "your_domain.onmicrosoft.com",
    "TenantId": "your_tenant_id",
    "ClientId": "your_client_id",
    "CallbackPath": "/signin-oidc"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  }
}
```

### Summary

- **Azure AD** provides robust identity services for secure authentication and authorization.
- **Angular** applications can integrate with Azure AD using MSAL for authentication flows.
- **.NET Core** APIs can secure endpoints using Azure AD authentication middleware.
- Ensure proper configuration, token management, and secure API access when integrating Azure AD with Angular and .NET Core.
