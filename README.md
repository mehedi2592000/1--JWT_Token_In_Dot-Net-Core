Welcome to Jwt token in dot net core and dot net core mvc 

There have many token authentication but jwt beacuse jwt token store  in json file. suppose you use anothe token base authentication then you are phase one problem that is if you use load balanching server managment then you reques but this request is going to server1 and store the token . after that you sent the another request it going to server 2 but this server does not know your token so give the error. it use redis store base . so jwt use json file to store token thats why it does not face any problem 

```
Code :: For all 
Step 1: Download "Microsoft.AspNetCore.Authentication.JwtBearer" Package 

Step-2: appsetting.json
    "Jwt": {
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "SecretKey": "this is my custom Secret key for authentication"
  }

Step-3 : Program.cs
              builder.Services.AddScoped<TokenController>();
              builder.Services.AddAuthentication(options =>
              {
                  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
              }).AddJwtBearer(options =>
              {
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      ValidateIssuer = true,
                      ValidateAudience = true,
                      ValidateLifetime = true,
                      ValidateIssuerSigningKey = true,
                      ValidIssuer = builder.Configuration["Jwt:Issuer"],
                      ValidAudience = builder.Configuration["Jwt:Audience"],
                      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]))
                  };
              });

Step-4 : Program.cs
          app.UseAuthentication();
          

Step-5: TokenController 
        [HttpPost]
        public IActionResult Login(LoginModel model)
        {
            // TODO: Implement proper user authentication here
            // For simplicity, a dummy check is performed here
            if (model.username == "abc" && model.username == "abc")
            {
                var token = GenerateToken(model.username);               
                return Ok(new { Token = token });
            }
            return Unauthorized();
        }
        private string GenerateToken(string username)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var authClaims = new List<Claim>();
            authClaims.Add(new Claim(ClaimTypes.Name, "user.FirstName + user.LastName"));
            authClaims.Add(new Claim("UserName", "user.FirstName +  + user.LastName"));
            authClaims.Add(new Claim("Email", "user.Email"));
            authClaims.Add(new Claim("UserId", "user.Id"));
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

Step-6: Login Model Add

step-7 ::  Add "[Authorize]"   which methode you want to authorize 
            OR
            Add "AllowAnonymous" which methode you do not authorize 

========================Thats it to Api========================================
----xxxxxxxxxxxxxxxx----------------------xxxxxxxxxxxxxxxx--------------xxxxxxx
==================== Extra code for MVC use ===================================
More help : https://stackoverflow.com/questions/77467181/issue-with-using-jwt-for-authentication-in-asp-net-core-mvc
Role Base Authentication :: https://ravindradevrani.medium.com/net-7-jwt-authentication-and-role-based-authorization-5e5e56979b67
=========================================================================================================
Step-1-1: Program.cs 
   =>       builder.Services.AddSession(options =>
          {
              options.IdleTimeout = TimeSpan.FromMinutes(30); // Adjust as needed
          });
    =>     app.UseSession();
    =>     app.Use(async (context, next) =>
            {                
                var token = context.Session.GetString("AccessToken");            
                if (!string.IsNullOrEmpty(token) &&
                    !context.Request.Headers.ContainsKey("Authorization"))
                {
                    context.Request.Headers.Add("Authorization", "Bearer " + token);
                }            
                await next();
            });
      =>    app.UseAuthentication();
            app.UseAuthorization();

step-1-2: Token Controller 
           public IActionResult Login(LoginModel model)
        {
            // TODO: Implement proper user authentication here
            // For simplicity, a dummy check is performed here
            if (model.username == "abc" && model.username == "abc")
            {
                var token = GenerateToken(model.username);
                        HttpContext.Session.SetString("AccessToken", token);     // extra this line add
                return Ok(new { Token = token });
            }
            return Unauthorized();
        }
```
