using NSec.Cryptography;
using System.Text;
using System.Text.Json;
using PublicKey = NSec.Cryptography.PublicKey;

namespace JwtEd25519Validation
{
    // Кастомное исключение для ошибок валидации токена
    public class TokenException : Exception
    {
        public TokenException(string message) : base(message) { }
    }

    public class TokenValidatorTest
    {
        /// <summary>
        /// Метод для валидации JWT токена.
        /// Шаги:
        /// 1. Определяем публичный ключ в формате JWK (JSON).
        /// 2. Извлекаем из JSON параметр "x" и выполняем Base64Url-декодирование.
        /// 3. Импортируем публичный ключ через NSec.Cryptography.
        /// 4. Разбиваем JWT токен на части (header, payload, signature).
        /// 5. Восстанавливаем сообщение (header.payload) и Base64Url-декодируем подпись.
        /// 6. Проверяем подпись с помощью алгоритма Ed25519.
        /// 7. Извлекаем payload, парсим его как JSON и проверяем claim "exp" (срок действия).
        /// </summary>
        /// <param name="token">JWT токен</param>
        /// <returns>true, если токен валиден, иначе выбрасывается исключение</returns>
        public bool VerifyToken(string token)
        {
            try
            {
                // Публичный ключ в формате JWK
                string publicKeyContent = @"{
                    ""kty"":""OKP"",
                    ""crv"":""Ed25519"",
                    ""kid"":""center"",
                    ""x"":""YMnORlpGq-K8clpvw3Uu82yT-81CNgixZlnIwKpJVx4""
                }";

                // Парсим JSON с публичным ключом
                using (JsonDocument doc = JsonDocument.Parse(publicKeyContent))
                {
                    JsonElement root = doc.RootElement;
                    string x = root.GetProperty("x").GetString();

                    // Декодируем параметр "x" из Base64Url (он представляет собой 32 байта)
                    byte[] publicKeyBytes = Base64UrlDecode(x);

                    // Импортируем публичный ключ через NSec.
                    // Формат RawPublicKey соответствует "сырым" 32 байтам публичного ключа.
                    var algorithm = SignatureAlgorithm.Ed25519;
                    PublicKey publicKey = PublicKey.Import(algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);

                    // Разбиваем JWT токен на части (должно быть 3 части: header, payload, signature)
                    string[] parts = token.Trim().Split('.');
                    if (parts.Length != 3)
                        throw new Exception("Неверный формат JWT токена.");

                    string headerEncoded = parts[0];
                    string payloadEncoded = parts[1];
                    string signatureEncoded = parts[2];

                    // Восстанавливаем сообщение, над которым была вычислена подпись: header + "." + payload
                    string message = $"{headerEncoded}.{payloadEncoded}";
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);

                    // Декодируем подпись из Base64Url
                    byte[] signature = Base64UrlDecode(signatureEncoded);

                    // Проверяем подпись. Если проверка не пройдена – выбрасываем исключение.
                    if (!algorithm.Verify(publicKey, messageBytes, signature))
                    {
                        throw new Exception("Проверка подписи токена не пройдена.");
                    }

                    // Декодируем payload и парсим JSON для извлечения claims.
                    byte[] payloadBytes = Base64UrlDecode(payloadEncoded);
                    string payloadJson = Encoding.UTF8.GetString(payloadBytes);
                    using (JsonDocument payloadDoc = JsonDocument.Parse(payloadJson))
                    {
                        JsonElement payloadRoot = payloadDoc.RootElement;
                        // Проверяем наличие claim "exp" (время истечения)
                        if (payloadRoot.TryGetProperty("exp", out JsonElement expElement))
                        {
                            long expUnix = expElement.GetInt64();
                            DateTimeOffset expDateTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);

                            if (expDateTime < DateTimeOffset.UtcNow)
                            {
                                throw new Exception("Токен просрочен.");
                            }
                        }
                        else
                        {
                            throw new Exception("Токен не содержит claim 'exp'.");
                        }
                    }
                }

                // Если все проверки прошли успешно, возвращаем true
                return true;
            }
            catch (Exception ex)
            {
                throw new TokenException(ex.Message);
            }
        }

        /// <summary>
        /// Метод для декодирования строки в формате Base64Url в массив байтов.
        /// Base64Url отличается от стандартного Base64 символами '-' вместо '+' и '_' вместо '/',
        /// а также отсутствием символов '=' для выравнивания.
        /// </summary>
        private static byte[] Base64UrlDecode(string input)
        {
            string s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    s += "==";
                    break;
                case 3:
                    s += "=";
                    break;
                default:
                    throw new Exception("Неверная строка в формате Base64Url.");
            }
            return Convert.FromBase64String(s);
        }
    }

    // Пример использования
    class Program
    {
        static void Main(string[] args)
        {
            string token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJjZW50ZXIiLCJpYXQiOjE3Mzk1MDc0MDAsImV4cCI6MTczOTY4MDIwMH0.WRjpJ-2RfjuOL5P6TYJLKX9mVN0O2HCxg4Cl32D_tm_3s5DJODpLjbOj1qXTYALEIaFfWQ697h0G_ZEDgfrfDQ";
            TokenValidatorTest tokenValidatorTest = new TokenValidatorTest();

            try
            {
                bool result = tokenValidatorTest.VerifyToken(token);
                Console.WriteLine($"Токен валиден: {result}");
            }
            catch (TokenException ex)
            {
                Console.WriteLine($"Ошибка валидации токена: {ex.Message}");
            }
        }
    }
}
