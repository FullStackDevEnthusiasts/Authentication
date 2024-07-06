JSON Web Token (JWT) Authentication is a token-based authentication method that allows users to securely transmit information between parties as a JSON object. JWTs are compact, URL-safe, and can be digitally signed and optionally encrypted. They are commonly used in web applications and APIs for authentication and information exchange. Here's a detailed explanation of JWT Authentication:

### Components of JWT

JWTs consist of three parts separated by dots (`.`):

1. **Header**: Typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

   Example:
   ```
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```

2. **Payload (Claims)**: Contains the actual information (claims) being transmitted. Claims are statements about an entity (typically the user) and additional metadata.

   Example:
   ```
   {
     "sub": "1234567890",
     "name": "John Doe",
     "admin": true
   }
   ```

   There are three types of claims:
   - **Registered claims**: Predefined claims such as `iss` (issuer), `exp` (expiration time), `sub` (subject), etc.
   - **Public claims**: Custom claims defined by those using JWTs.
   - **Private claims**: Custom claims agreed upon between parties.

3. **Signature**: Used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way. The signature is created by combining the encoded header, encoded payload, a secret (for HMAC algorithms) or a private key (for RSA algorithms), and the specified algorithm.

   Example (pseudo-code):
   ```
   HMACSHA256(
     base64UrlEncode(header) + "." +
     base64UrlEncode(payload),
     secret
   )
   ```

### How JWT Authentication Works

1. **Authentication**:
   - The client (typically a web application or a mobile app) sends credentials (e.g., username and password) to the server.
   - The server verifies the credentials and generates a JWT if the authentication is successful.

2. **Authorization**:
   - Upon subsequent requests, the client includes the JWT in the `Authorization` header of the HTTP request.
   - The server verifies the JWT's signature and decodes the claims to identify the user and check permissions.

3. **Validation**:
   - The server checks the signature to ensure the JWT is valid and not tampered with.
   - It also verifies that the token is not expired and that it has the correct issuer (`iss`) and audience (`aud`) as specified.

4. **Information Exchange**:
   - The server can extract information from the claims (e.g., user ID, roles) without needing to query a database or session store.
   - This makes JWTs efficient and suitable for stateless authentication, where servers don't need to keep track of sessions.

### Benefits of JWT Authentication

- **Compact and URL-safe**: Easy to send over HTTP and store in cookies, headers, or URLs.
- **Stateless**: Servers don't need to keep session state, which scales well in distributed systems.
- **Secure**: Signed JWTs ensure integrity, and encrypted JWTs provide confidentiality.
- **Standardized**: JWTs are based on open standards (RFC 7519), making them interoperable across different platforms and languages.

### Example Use Case

1. **User Authentication**:
   - User logs in with username and password.
   - Server validates credentials and generates a JWT containing user information and permissions.
   - JWT is returned to the client and stored (e.g., in local storage or a cookie).

2. **Subsequent Requests**:
   - Client includes the JWT in the `Authorization` header of API requests.
   - Server verifies the JWT's signature and extracts user information from claims to authenticate and authorize the request.

JWT Authentication is widely used in modern web development for its simplicity, security, and efficiency in handling authentication and authorization across distributed systems and APIs. Proper implementation includes secure token storage, careful validation, and consideration of token expiration and revocation policies to maintain security.

To demonstrate JWT Authentication with Angular 13, .NET Core 6, and SQL Server, including storing the token in localStorage and using interceptors, we'll create a simple application with user login functionality.

### Backend Implementation (ASP.NET Core 6)

#### 1. Setup .NET Core Web API Project

Assuming you have .NET Core 6 SDK installed, follow these steps:

1. Create a new .NET Core Web API project:
   ```bash
   dotnet new webapi -o JwtAuthDemo
   cd JwtAuthDemo
   ```

2. Install required NuGet packages:
   ```bash
   dotnet add package Microsoft.EntityFrameworkCore.SqlServer
   dotnet add package Microsoft.EntityFrameworkCore.Design
   dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
   ```

3. Scaffold Identity for authentication:
   ```bash
   dotnet aspnet-codegenerator identity -dc ApplicationDbContext --files "Account.Register;Account.Login"
   ```

4. Configure JWT Authentication in `Startup.cs`:
   ```csharp
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
           IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration["Jwt:SecretKey"])),
           ValidateIssuer = false,
           ValidateAudience = false
       };
   });

   // Add authorization policy
   services.AddAuthorization(options =>
   {
       options.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
           .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
           .RequireAuthenticatedUser()
           .Build());
   });
   ```

5. Create a `JwtService.cs` for token generation:
   ```csharp
   public class JwtService
   {
       private readonly IConfiguration _configuration;

       public JwtService(IConfiguration configuration)
       {
           _configuration = configuration;
       }

       public string GenerateToken(string userId, string userName)
       {
           var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
           var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

           var claims = new List<Claim>
           {
               new Claim(JwtRegisteredClaimNames.Sub, userId),
               new Claim("username", userName),
               new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
           };

           var token = new JwtSecurityToken(
               issuer: _configuration["Jwt:Issuer"],
               audience: _configuration["Jwt:Audience"],
               claims: claims,
               expires: DateTime.UtcNow.AddHours(1),
               signingCredentials: credentials
           );

           return new JwtSecurityTokenHandler().WriteToken(token);
       }
   }
   ```

6. Implement login endpoint in `AccountController.cs`:
   ```csharp
   [HttpPost("login")]
   public async Task<IActionResult> Login(LoginModel model, [FromServices] UserManager<ApplicationUser> userManager, [FromServices] JwtService jwtService)
   {
       var user = await userManager.FindByNameAsync(model.UserName);
       if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
       {
           var token = jwtService.GenerateToken(user.Id, user.UserName);
           return Ok(new { Token = token });
       }

       return Unauthorized();
   }
   ```

#### 2. Frontend Implementation (Angular 13)

Assuming you have Angular CLI and Node.js installed:

1. Create a new Angular project:
   ```bash
   ng new angular-jwt-demo
   cd angular-jwt-demo
   ```

2. Implement JWT Interceptor (`jwt.interceptor.ts`):
   ```typescript
   import { Injectable } from '@angular/core';
   import { HttpInterceptor, HttpEvent, HttpRequest, HttpHandler } from '@angular/common/http';
   import { Observable } from 'rxjs';

   @Injectable()
   export class JwtInterceptor implements HttpInterceptor {
       intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
           const token = localStorage.getItem('token');
           if (token) {
               req = req.clone({
                   setHeaders: {
                       Authorization: `Bearer ${token}`
                   }
               });
           }
           return next.handle(req);
       }
   }
   ```

3. Provide the interceptor in `app.module.ts`:
   ```typescript
   import { NgModule } from '@angular/core';
   import { BrowserModule } from '@angular/platform-browser';
   import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
   import { JwtInterceptor } from './jwt.interceptor';

   import { AppRoutingModule } from './app-routing.module';
   import { AppComponent } from './app.component';

   @NgModule({
       declarations: [
           AppComponent
       ],
       imports: [
           BrowserModule,
           AppRoutingModule,
           HttpClientModule
       ],
       providers: [
           { provide: HTTP_INTERCEPTORS, useClass: JwtInterceptor, multi: true }
       ],
       bootstrap: [AppComponent]
   })
   export class AppModule { }
   ```

4. Implement login functionality in a component (`login.component.ts`):
   ```typescript
   import { Component } from '@angular/core';
   import { HttpClient } from '@angular/common/http';

   @Component({
       selector: 'app-login',
       template: `
           <form (submit)="login()">
               <input type="text" [(ngModel)]="username" placeholder="Username">
               <input type="password" [(ngModel)]="password" placeholder="Password">
               <button type="submit">Login</button>
           </form>
       `
   })
   export class LoginComponent {
       username: string;
       password: string;

       constructor(private http: HttpClient) { }

       login() {
           this.http.post<any>('https://localhost:5001/api/account/login', { userName: this.username, password: this.password })
               .subscribe(response => {
                   localStorage.setItem('token', response.token);
                   // Redirect or handle successful login
               }, error => {
                   console.error('Login error:', error);
                   // Handle login error
               });
       }
   }
   ```

5. Replace `https://localhost:5001` with your .NET Core API URL.

### SQL Database

Ensure your `ApplicationDbContext` is configured to use SQL Server as per your .NET Core setup with Identity. This involves configuring connection strings in `appsettings.json` or `appsettings.Development.json`.

### Summary

- **Backend**: ASP.NET Core 6 Web API with JWT authentication, storing tokens in localStorage, and SQL Server for user data storage.
- **Frontend**: Angular 13 with HTTP interceptor for JWT token handling and login functionality.

This setup provides a basic implementation of JWT Authentication between Angular 13 and .NET Core 6, demonstrating secure user authentication and authorization using tokens. Adjust configurations and error handling as per your application's specific requirements and security practices.
