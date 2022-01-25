using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Service
{
    public class EmailSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;
        public EmailSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string emailAdress)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            Execute(emailAdress, code).Wait();
            return code;
        }

        private async Task Execute(string email, string code)
        {
            //var client = new SendGridClient(_twoFactorOptions.SendGrid_ApiKey);
            //var from = new EmailAddress("mjasonmadison@gmail.com");
            //var subject = "İki Adımlı Kimlik Doğrulama Kodunuz";
            //var to = new EmailAddress(email);
            //var htmlContent = $"<h2>Siteye giriş yapabilmek için doğrulama kodunuz aşağıdadır.</h2><h3>Kodunuz:{code}</h3>";
            //var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            //var response = await client.SendEmailAsync(msg);

            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("smtp.gmail.com");

            mail.From = new MailAddress("mjasonmadison@gmail.com");
            mail.To.Add(email);

            mail.Subject = $"www.bıdıbıdı.com::E-Mail Doğrulama";
            mail.Body = $"<h2>Siteye giriş yapabilmek için doğrulama kodunuz aşağıdadır.</h2><hr/><h3>Kodunuz:{code}</h3>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.EnableSsl = true;
            smtpClient.Credentials = new System.Net.NetworkCredential("mjasonmadison@gmail.com", "123madison");

            smtpClient.Send(mail);
        }
    }
}
