Token-Based Authentication is a more secure and versatile approach compared to Basic Authentication. It involves generating and verifying tokens, typically JSON Web Tokens (JWTs), which are used to authenticate requests. Here’s how you can implement Token-Based Authentication in Angular and .NET Core 6:

### Angular Implementation

In Angular, Token-Based Authentication involves storing the token (usually in local storage or session storage) and sending it in the `Authorization` header with each HTTP request.

1. **Service Implementation** (e.g., `auth.service.ts`):

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://your-api-url.com/api'; // Replace with your API URL
  private token: string;

  constructor(private http: HttpClient) { }

  login(username: string, password: string) {
    return this.http.post<any>(`${this.apiUrl}/auth/login`, { username, password }).pipe(
      tap(response => {
        if (response && response.token) {
          this.token = response.token;
          localStorage.setItem('token', this.token); // Store token in localStorage
        }
      })
    );
  }

  logout() {
    this.token = null;
    localStorage.removeItem('token'); // Remove token from localStorage
  }

  isLoggedIn() {
    return !!localStorage.getItem('token'); // Check if token exists
  }

  getAuthorizationHeader() {
    return new HttpHeaders({
      Authorization: `Bearer ${this.token}`
    });
  }

  getData() {
    const headers = this.getAuthorizationHeader();
    return this.http.get<any>(`${this.apiUrl}/data`, { headers });
  }
}
```

2. **Component Usage**:

```typescript
import { Component } from '@angular/core';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-login',
  template: `
    <form (ngSubmit)="login()">
      <input type="text" [(ngModel)]="username" placeholder="Username">
      <input type="password" [(ngModel)]="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
  `
})
export class LoginComponent {
  username: string;
  password: string;

  constructor(private authService: AuthService) { }

  login() {
    this.authService.login(this.username, this.password).subscribe(
      data => {
        // Handle successful login
      },
      error => {
        // Handle login error
      }
    );
  }
}
```

### .NET Core 6 Implementation

In .NET Core 6, Token-Based Authentication can be implemented using JWT (JSON Web Tokens). ASP.NET Core provides middleware to validate and process JWT tokens.

1. **Configure JWT Authentication** (e.g., `Startup.cs`):

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

public void ConfigureServices(IServiceCollection services)
{
    // JWT configuration
    var key = Encoding.ASCII.GetBytes("your-secret-key"); // Replace with your secret key
    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false; // Change to true in production
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });

    // Other services and configurations
}

public void Configure(IApplicationBuilder app)
{
    // Use authentication middleware
    app.UseAuthentication();

    // Other middleware and configurations
}
```

2. **Generate and Validate JWT Tokens** (e.g., `AuthController.cs`):

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config = config;
    }

    [HttpPost("login")]
    public IActionResult Login(LoginModel model)
    {
        // Replace with your authentication logic (e.g., check username and password against database)
        if (IsValidUser(model.Username, model.Password))
        {
            var token = GenerateJwtToken(model.Username);
            return Ok(new { token });
        }

        return Unauthorized();
    }

    private bool IsValidUser(string username, string password)
    {
        // Replace with your authentication logic (e.g., check username and password against database)
        return username == "admin" && password == "admin";
    }

    private string GenerateJwtToken(string username)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

### Explanation:

- **Angular**: The `AuthService` manages token storage (in localStorage), login/logout functionality, and provides methods (`getAuthorizationHeader()`) to attach the token to HTTP requests. Upon successful login, the server responds with a JWT token, which is then stored and used for subsequent requests.

- **.NET Core 6**: The application is configured to use JWT authentication (`AddJwtBearer` middleware) with specified validation parameters. The `AuthController` handles the login process, validates user credentials, and generates a JWT token using `JwtSecurityTokenHandler`. This token is returned to the client upon successful authentication and must be included in subsequent requests in the `Authorization` header as `Bearer <token>`.

Token-Based Authentication provides better security compared to Basic Authentication as tokens can expire, be revoked, and carry additional user information (claims). It's crucial to securely store and transmit tokens, often using HTTPS to prevent interception and tampering.
