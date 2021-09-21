using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Helper
{
    public static class EmailConfirmation
    {
        public static void SendEmail(string link, string email)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("smtp.gmail.com");

            mail.From = new MailAddress("mjasonmadison@gmail.com");
            mail.To.Add(email);

            mail.Subject = $"www.bıdıbıdı.com::E-Mail Doğrulama";
            mail.Body = "<h2>E-Mail Doğrulama için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href='{link}'>E-Mail Doğrulama linki.</a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.EnableSsl = true;
            smtpClient.Credentials = new System.Net.NetworkCredential("mjasonmadison@gmail.com", "123madison");

            smtpClient.Send(mail);
        }
    }
}
