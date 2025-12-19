using System.Text.RegularExpressions;

namespace API.Gateway.Services;
 
    public static class SqlInjectionDetector
    {
        private static readonly Regex SqlInjectionRegex = new(
            @"(\b(select|insert|update|delete|drop|union|exec|execute)\b|--|;|'|"")",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static (bool HasSqlInjection,string AnormalValue) HasSqlInjection(params string[] inputs)
        {
            foreach (var input in inputs)
            {
                if (string.IsNullOrWhiteSpace(input))
                    continue;

                if (SqlInjectionRegex.IsMatch(input))
                    return (true,input);
            }

            return (false,string.Empty);
        }
    }

 
