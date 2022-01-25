using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Service
{
    public class TwoFactorService
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly UrlEncoder _urlEncoder;
        public TwoFactorService(IOptions<TwoFactorOptions> options, UrlEncoder urlEncoder)
        {
            _twoFactorOptions = options.Value;
            _urlEncoder = urlEncoder;
        }

        public string GenerateQrCodeUri(string email, string unformattedKey)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            return string.Format(format, _urlEncoder.Encode("www.uyeliksistemi.com"), _urlEncoder.Encode(email), unformattedKey);
        }

        public int GetCodeVerification()
        {
            Random rnd = new Random();
            return rnd.Next(1000, 9999);
        }

        //Sesson'dan bilgi okuyacağından dolayı HttpContext nesnesi alıyor.
        public int TimeLeft(HttpContext context)
        {
            if (context.Session.GetString("currentTime") == null)
            {
                context.Session.SetString("currentTime", DateTime.Now.AddSeconds(_twoFactorOptions.CodeTimeExpire).ToString());
            }
            DateTime currentTime = DateTime.Parse(context.Session.GetString("currentTime").ToString());

            //TotalSeconds ikisi arasındaki farkı dooble tipinde döner.
            int timeLeft = (int)(currentTime - DateTime.Now).TotalSeconds;

            if (timeLeft <= 0)
            {
                context.Session.Remove("currentTime");
                return 0;
            }
            else
            {
                return timeLeft;
            }
        }
    }
}
