namespace WebApplication1.Utils
{
    public static class Base64UrlHelper
    {
        /// <summary>
        /// Декодирует строку в формате Base64Url в массив байтов.
        /// </summary>
        public static byte[] Decode(string input)
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
}
