using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
// using YourApp.Data; // Apnar DbContext namespace

var builder = WebApplication.CreateBuilder(args);

// Kestrel Server Hardening (Max 30 MB Body for Product Photos)
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 30 * 1024 * 1024;
});

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 30 * 1024 * 1024;
});

builder.Services.AddControllersWithViews();

// Proxy IP Header (Cloudflare / Load Balancer)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = null;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Secure Session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "__App.Secure.Session";
    options.IdleTimeout = TimeSpan.FromMinutes(45);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

// CGNAT & Mobile Network Friendly Sliding Window Rate Limiter
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("LeadSpamProtection", context =>
    {
        var cfIp = context.Request.Headers["CF-Connecting-IP"].FirstOrDefault();
        var forwardedIp = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim();
        var clientIp = !string.IsNullOrEmpty(cfIp) ? cfIp
                     : !string.IsNullOrEmpty(forwardedIp) ? forwardedIp
                     : context.Connection.RemoteIpAddress?.ToString() ?? "unknown_ip";

        return RateLimitPartition.GetSlidingWindowLimiter(clientIp, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 3,
            QueueLimit = 2
        });
    });
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseForwardedHeaders();
app.UseHttpsRedirection();

// In-Memory WAF: Scanner & Exploit Blocker
var blockedScannerAgents = new[]
{
    "sqlmap", "nikto", "nmap", "nuclei", "dirbuster", "gobuster",
    "ffuf", "wpscan", "acunetix", "nessus", "masscan", "zgrab"
};

var forbiddenPaths = new[]
{
    "/.env", "/.git", "/wp-admin", "/wp-login", "/phpmyadmin",
    "/appsettings", "/web.config"
};

app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? string.Empty;
    var query = context.Request.QueryString.Value ?? string.Empty;
    var userAgent = context.Request.Headers.UserAgent.ToString();

    if (HttpMethods.IsTrace(context.Request.Method) || context.Request.Method.Equals("TRACK", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        return;
    }

    if (!string.IsNullOrEmpty(userAgent))
    {
        for (int i = 0; i < blockedScannerAgents.Length; i++)
        {
            if (userAgent.Contains(blockedScannerAgents[i], StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        }
    }

    for (int i = 0; i < forbiddenPaths.Length; i++)
    {
        if (path.StartsWith(forbiddenPaths[i], StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
    }

    if (path.Contains("/..", StringComparison.Ordinal) ||
        path.Contains("\\..", StringComparison.Ordinal) ||
        query.Contains("../", StringComparison.Ordinal) ||
        query.Contains("%00", StringComparison.Ordinal) ||
        query.Contains("<script", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    await next();
});

// OWASP Security Headers (E-Commerce Optimized)
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=()";
    context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";
    context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups";
    context.Response.Headers["Cross-Origin-Resource-Policy"] = "cross-origin";

    if (context.Request.Path.StartsWithSegments("/Admin", StringComparison.OrdinalIgnoreCase) ||
        context.Request.Path.StartsWithSegments("/Leads", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
    }

    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "base-uri 'self'; " +
        "form-action 'self' https://www.facebook.com https://connect.facebook.net https://wa.me https://api.whatsapp.com https: tel: mailto:; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: " +
            "https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com " +
            "https://connect.facebook.net https://www.googletagmanager.com https://tagmanager.google.com " +
            "https://www.google-analytics.com https://googleads.g.doubleclick.net https://www.googleadservices.com " +
            "https://www.clarity.ms https://scripts.clarity.ms https://*.clarity.ms https://analytics.tiktok.com; " +
        "style-src 'self' 'unsafe-inline' https: https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
        "font-src 'self' data: https: https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data: blob: https: http:; " +
        "connect-src 'self' https: https://connect.facebook.net https://*.facebook.com https://*.google-analytics.com https://*.clarity.ms https://*.tiktokw.us; " +
        "frame-src 'self' https: https://www.facebook.com https://www.youtube.com;";

    context.Response.OnStarting(() =>
    {
        context.Response.Headers.Remove("Server");
        context.Response.Headers.Remove("X-Powered-By");
        context.Response.Headers.Remove("X-AspNet-Version");
        return Task.CompletedTask;
    });

    await next();
});

app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseSession();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
