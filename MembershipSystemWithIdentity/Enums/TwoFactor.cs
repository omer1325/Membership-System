using System.ComponentModel.DataAnnotations;

namespace MembershipSystemWithIdentity.Enums
{
    public enum TwoFactor
    {
        [Display(Name = "Hiç biri")]
        None = 0,
        [Display(Name = "Telefon ile kimlik doğrulama")]
        Phone = 1,
        [Display(Name = "Email ile kimlik doğrulama")]
        Email = 2,
        [Display(Name = "Microsoft/Google Authenticator ile kimlik doğrulama")]
        MicrosoftGoogle = 3
    }
}
