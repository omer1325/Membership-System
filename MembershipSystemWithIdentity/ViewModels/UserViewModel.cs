using MembershipSystemWithIdentity.Enums;
using System;
using System.ComponentModel.DataAnnotations;
namespace MembershipSystemWithIdentity.ViewModels
{
    public class UserViewModel
    {
        [Required(ErrorMessage = "Kullanıcı İsmi gereklidir.")]
        [Display(Name = "Kullanıcı Adı")]
        public string UserName { get; set; }

        [Display(Name = "Telefon No:")]
        [RegularExpression(@"^(0(\d{3}) (\d{3}) (\d{2}) (\d{2}))$", ErrorMessage = "Telefon numarası uygun formatta değil")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "Email adresi gereklidir.")]
        [Display(Name = "Email adresi")]
        [EmailAddress(ErrorMessage ="Email adresiniz doğru formatta değil.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Kullanıcı şifresi gereklidir.")]
        [Display(Name = "Şifre")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Doğum tarihi")]
        [DataType(DataType.Date)]
        public DateTime? BirthDay { get; set; }

        public string Picture { get; set; }

        [Display(Name = "Şehir")]
        public string City { get; set; }

        [Display(Name = "Cinsiyet")]
        public Gender Gender { get; set; }
    }
}
