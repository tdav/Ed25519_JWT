using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using WebApplication1.Utils;

public class Ed25519AuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly TokenValidatorTest _tokenValidator;

    public Ed25519AuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _tokenValidator = new TokenValidatorTest();
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Проверяем наличие заголовка Authorization
        if (!Request.Headers.ContainsKey("Authorization"))
            return Task.FromResult(AuthenticateResult.Fail("Отсутствует заголовок Authorization."));

        string authorizationHeader = Request.Headers["Authorization"];

        if (string.IsNullOrEmpty(authorizationHeader))
            return Task.FromResult(AuthenticateResult.Fail("Пустой заголовок Authorization."));

        if (!authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(AuthenticateResult.Fail("Неверная схема авторизации."));

        string token = authorizationHeader.Substring("Bearer ".Length).Trim();

        try
        {
            // Валидируем токен
            bool isValid = _tokenValidator.VerifyToken(token);
            if (!isValid)
                return Task.FromResult(AuthenticateResult.Fail("Токен не валиден."));

            // Если токен валиден, извлекаем полезную нагрузку для формирования ClaimsPrincipal
            // JWT имеет формат: header.payload.signature
            string[] parts = token.Split('.');
            string payloadEncoded = parts[1];
            byte[] payloadBytes = Base64UrlHelper.Decode(payloadEncoded);
            string payloadJson = Encoding.UTF8.GetString(payloadBytes);

            // Парсим JSON и извлекаем claims (например, "sub" и "exp")
            var claims = new List<Claim>();
            using (JsonDocument payloadDoc = JsonDocument.Parse(payloadJson))
            {
                JsonElement root = payloadDoc.RootElement;

                if (root.TryGetProperty("sub", out JsonElement subElement))
                {
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, subElement.GetString()));
                }

                if (root.TryGetProperty("exp", out JsonElement expElement))
                {
                    claims.Add(new Claim("exp", expElement.GetInt64().ToString()));
                }
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            var res = AuthenticateResult.Success(ticket);

            return Task.FromResult(res);
        }
        catch (Exception ex)
        {
            return Task.FromResult(AuthenticateResult.Fail($"Ошибка аутентификации: {ex.Message}"));
        }
    }
}
