using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using RestSharp;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Service
{
    public class SmsSender
    {
        private IConfiguration _configuration { get; }
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;
        public SmsSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService, IConfiguration configuration)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
            _configuration = configuration;
        }

        public string Send(string phone)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            //Sms provider codes
            Execute(phone, code).Wait();

            return code;
        }

        public async Task Execute(string phone, string code)
        {
            //var accountSid = _twoFactorOptions.ACCOUNT_SID;
            //var authToken = _twoFactorOptions.AUTH_TOKEN;
            //TwilioClient.Init(accountSid, authToken);

            //var to = new PhoneNumber(phone);
            //var from = new PhoneNumber("+12677109507");

            //var message = await MessageResource.CreateAsync(
            //    to: to,
            //    from: from,
            //    body: $"Siteye giriş yapabilmek için doğrulama kodunuz {code}");
            var apiKey = _configuration["Authentication:Thetexting:Api_Key"];
            var apiSecret = _configuration["Authentication:Thetexting:Api_Secret"];
            var client = new RestClient("https://www.thetexting.com/rest/sms/json/message/send");

                var request = new RestRequest(Method.POST);
                request.AddHeader("content-type", "application/x-www-form-urlencoded");
                request.AddHeader("cache-control", "no-cache");
                request.AddParameter("application/x-www-form-urlencoded", $"api_secret={apiSecret}&api_key={apiKey}&from=test&to=9{phone}&text={code}&type=text", ParameterType.RequestBody);
                IRestResponse response = client.Execute(request);
        }
	}
}