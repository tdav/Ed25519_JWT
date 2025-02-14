using NSec.Cryptography;
using NSec.Cryptography;
using System;
using System.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json;
using WebApplication1.Utils;

namespace WebApplication1.Utils
{


    public class TokenException : Exception
    {
        public TokenException(string message) : base(message) { }
    }

    public class TokenValidatorTest
    {
        /// <summary>
        /// Проверяет валидность JWT‑токена.
        /// Если токен валиден, возвращает true, иначе выбрасывает TokenException.
        /// </summary>
        public bool VerifyToken(string token)
        {
            try
            {
                // Публичный ключ в формате JWK
                string publicKeyContent = @"{
                ""kty"": ""OKP"",
                ""crv"": ""Ed25519"",
                ""kid"": ""center"",
                ""x"": ""12nORlpGq-K8clpvw3Uu82yT-12CNgixZlnIwKpJVx4""
            }";

                // Парсим JSON с публичным ключом
                using (JsonDocument doc = JsonDocument.Parse(publicKeyContent))
                {
                    JsonElement root = doc.RootElement;
                    string x = root.GetProperty("x").GetString();

                    // Декодируем параметр "x" из Base64Url
                    byte[] publicKeyBytes = Base64UrlHelper.Decode(x);

                    // Импортируем публичный ключ через NSec.
                    var algorithm = SignatureAlgorithm.Ed25519;
                    PublicKey publicKey = PublicKey.Import(algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);

                    // Разбиваем JWT-токен на части (header, payload, signature)
                    string[] parts = token.Trim().Split('.');
                    if (parts.Length != 3)
                        throw new Exception("Неверный формат JWT токена.");

                    string headerEncoded = parts[0];
                    string payloadEncoded = parts[1];
                    string signatureEncoded = parts[2];

                    // Восстанавливаем сообщение (header + "." + payload)
                    string message = $"{headerEncoded}.{payloadEncoded}";
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);

                    // Декодируем подпись из Base64Url
                    byte[] signature = Base64UrlHelper.Decode(signatureEncoded);

                    // Проверяем подпись
                    if (!algorithm.Verify(publicKey, messageBytes, signature))
                        throw new Exception("Проверка подписи токена не пройдена.");

                    // Декодируем payload и проверяем claim "exp"
                    byte[] payloadBytes = Base64UrlHelper.Decode(payloadEncoded);
                    string payloadJson = Encoding.UTF8.GetString(payloadBytes);
                    using (JsonDocument payloadDoc = JsonDocument.Parse(payloadJson))
                    {
                        JsonElement payloadRoot = payloadDoc.RootElement;
                        if (payloadRoot.TryGetProperty("exp", out JsonElement expElement))
                        {
                            long expUnix = expElement.GetInt64();
                            DateTimeOffset expDateTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);

                            if (expDateTime < DateTimeOffset.UtcNow)
                                throw new Exception("Токен просрочен.");
                        }
                        else
                        {
                            throw new Exception("Токен не содержит claim 'exp'.");
                        }
                    }
                }

                // Токен валиден
                return true;
            }
            catch (Exception e)
            {
                throw new TokenException(e.Message);
            }
        }
    }
}