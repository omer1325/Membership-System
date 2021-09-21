using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.ViewModels
{
    public class LoginViewModel
    {
        [Display(Name = "Email adresiniz")]
        [Required(ErrorMessage = "Email alanı gereklidir")]
        [EmailAddress]
        public string Email { get; set; }


        [Display(Name = "Şifreniz")]
        [Required(ErrorMessage = "Şifre girmeniz gereklidir")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakteli olmalıdır.")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }
    }
}
