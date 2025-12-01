namespace Stelark.Helpers
{
    public static class Extensions
    {
        public static string SanitizeFileName(this string name)
        {
            return RegexHelper.SanitizeFileName(name);
        }

        public static string NormalizeRequestID(this string id)
        {
            return RegexHelper.NormalizeRequestId(id);
        }

        public static string GetRequesterUser(this string requester)
        {
            var parts = requester.Split('\\');
            return parts.Length > 1 ? parts[1] : requester;
        }

        public static string GetPrincipalUser(this string principal)
        {
            if (principal.StartsWith("SAN:upn="))
            {
                return principal.Replace("SAN:upn=", "").Split('@')[0];
            }
            else if (principal.Contains("@"))
            {
                return principal.Split('@')[0];
            }
            return principal;
        }
    }
}