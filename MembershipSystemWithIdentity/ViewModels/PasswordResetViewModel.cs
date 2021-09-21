using System.ComponentModel.DataAnnotations;

namespace MembershipSystemWithIdentity.ViewModels
{
    public class PasswordResetViewModel
    {
        [Display(Name = "Email adresiniz")]
        [Required(ErrorMessage = "Email alanı gereklidir")]
        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "Yeni Şifreniz")]
        [Required(ErrorMessage = "Şifre girmeniz gereklidir")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakteli olmalıdır.")]
        public string PasswordNew { get; set; }
    }
}
