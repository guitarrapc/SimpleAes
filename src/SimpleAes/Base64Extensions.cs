using System;
using System.Collections.Generic;
using System.Text;

namespace SimpleAes
{
    public static class Base64Extensions
    {
        public static string ToBase64(this byte[] value) => Convert.ToBase64String(value);
        public static byte[] FromBase64(this string value) => Convert.FromBase64String(value);
    }
}
