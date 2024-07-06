Cookie-based authentication is a common approach where authentication information is stored in an HTTP cookie rather than being passed explicitly as headers or parameters with each request. This method is often used in web applications where sessions need to be maintained between the client (browser) and the server. Here’s how you can implement cookie-based authentication with Angular and .NET Core:

### Angular Frontend Integration

#### 1. Implement Authentication Service

Create an authentication service (`auth.service.ts`) to handle login, logout, and token acquisition using cookies:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private apiUrl = 'https://your-api.azurewebsites.net/api'; // Replace with your API URL

  constructor(private http: HttpClient) { }

  login(username: string, password: string) {
    return this.http.post<any>(`${this.apiUrl}/account/login`, { username, password }, { withCredentials: true });
  }

  logout() {
    return this.http.post<any>(`${this.apiUrl}/account/logout`, null, { withCredentials: true });
  }

  // Optional: Implement a method to check if the user is authenticated
  isAuthenticated() {
    return this.http.get<boolean>(`${this.apiUrl}/account/isauthenticated`, { withCredentials: true });
  }

}
```

#### 2. Secure API Requests

Ensure that credentials are sent with every request to maintain the authenticated session:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class ApiService {

  private apiUrl = 'https://your-api.azurewebsites.net/api'; // Replace with your API URL

  constructor(private http: HttpClient) { }

  getData() {
    return this.http.get<any>(`${this.apiUrl}/data`, { withCredentials: true });
  }

}
```

### .NET Core Backend Integration

#### 1. Configure Cookie Authentication

Configure cookie-based authentication in `Startup.cs`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Enable this in production with HTTPS
            options.LoginPath = "/account/login";
            options.LogoutPath = "/account/logout";
            options.AccessDeniedPath = "/account/accessdenied";
        });

    services.AddControllersWithViews();
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseHttpsRedirection(); // Enable this in production with HTTPS

    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();

    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");
    });
}
```

#### 2. Implement Account Controller

Create an account controller (`AccountController.cs`) to handle login, logout, and check authentication:

```csharp
[ApiController]
[Route("api/account")]
public class AccountController : ControllerBase
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            return Ok(new { message = "Login successful" });
        }

        return BadRequest(new { message = "Invalid credentials" });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { message = "Logout successful" });
    }

    [HttpGet("isauthenticated")]
    [Authorize]
    public IActionResult IsAuthenticated()
    {
        return Ok(true);
    }
}
```

### Summary

- **Cookie-based authentication** uses HTTP cookies to maintain user sessions.
- **Angular** applications send cookies with credentials in HTTP requests (`withCredentials: true`).
- **.NET Core** backend configures cookie authentication middleware and provides endpoints for login, logout, and session validation.
- Ensure secure cookie settings (`SecurePolicy` and `SameSite`) in production for protection against CSRF and other security threats. Adjust settings and error handling based on your application's requirements and security policies.
