using MembershipSystemWithIdentity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Mapster;
using MembershipSystemWithIdentity.ViewModels;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using MembershipSystemWithIdentity.Enums;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Security.Claims;
using System.Linq;

namespace MembershipSystemWithIdentity.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {
        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base (userManager, signInManager)
        {
        }

        public IActionResult Index()
        {
            //Buradaki Name, Database'deki UserName'ine denk gelir.
            //HttpContext'en Name'i bulur.
            AppUser user = CurrentUser;

            //user'dan gelen propertileri, UserViewModel ile eşleşenleri mapliyor.
            //UserViewModel modelin içindeki propertiler ile Database'deki stun isimleri aynı olmak zorunda
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }

        public IActionResult UserEdit()
        {
            AppUser user = CurrentUser;
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            //Bir tane DropDown oluşturduk ve içine Cinsiyetlerden oluşturduğumuz Enum'ı verdik.
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));


            return View(userViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture)
        {
            //UserViewModel'den password gelior ama bizim View kısmında bu alan yok. Bu alanı bundan dolayı çıkartıyoruz yoksa InValid geliyor.
            ModelState.Remove("Password");
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            if (ModelState.IsValid)
            {
                AppUser user = CurrentUser;
                //Kullanıcı bilgisine güncellerken, kayıtlı olan başkasının telefon numarasını güncellememesi için böyle bir koşul yazıyoruz.
                string phone = userManager.GetPhoneNumberAsync(user).Result;
                if (phone != userViewModel.PhoneNumber)
                {
                    if (userManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                    {
                        ModelState.AddModelError("", "Bu telefon numarası başka üye tarafından kullanılmaktadır.");
                        return View(userViewModel);
                    }
                }

                if (userPicture != null && userPicture.Length > 0)
                {
                    //GetExtension methodu, userPicture'dan gelen resimin uzantısını alacak. Örneğin jpg, png gibi.
                    //Burada resimlere Guid değer atayarak isimlendirme yapıyoruz.
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);

                    //GetCurrentDirectory methodu ile wwwroot klasörümüzün yolunu alıyoruz.
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/UserPicture", fileName);

                    //Stream boş ise FileMode ile bir path oluşturuyoruz.
                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);

                        //Veri tabanına kaydediyoruz.
                        user.Picture = "/UserPicture/" + fileName; 
                    }
                }

                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int) userViewModel.Gender;

                IdentityResult result = await userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    await userManager.UpdateSecurityStampAsync(user);
                    await signInManager.SignOutAsync();
                    //Burada şifre ile değilde, Cookie ile giriş yapıyoruz.
                    await signInManager.SignInAsync(user, true);

                    ViewBag.success = "true";
                }
                else
                {
                    AddModelError(result);
                }
            }

            return View(userViewModel);
        } 


        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]

        public IActionResult PasswordChange(PasswordChangeViewModel passwordChangeViewModel)
        {
            if (ModelState.IsValid)
            {
                //Buradaki Name bilgisi Cookie'den gelir. Database ile alakası yoktur.
                AppUser user = CurrentUser;

                    //Eski şifrenin doğru olup olmadığını kontrol ediyoruz.
                    bool exist = userManager.CheckPasswordAsync(user, passwordChangeViewModel.PasswordOld).Result;

                    if (exist)
                    {
                        IdentityResult result = userManager.ChangePasswordAsync(user, passwordChangeViewModel.PasswordOld, passwordChangeViewModel.PasswordNew).Result;


                        if (result.Succeeded)
                        {
                        userManager.UpdateSecurityStampAsync(user);
                        //Kullanıcı şifre değiştirdikten sonra arka tarafta kullanıcıya çıkış yaptırıp daha sonra giriş yaptırıyoruz.
                        //Eğer bu işlemi yapmazsak 30 dakika sonra Identity API 30 dk içerinde otomatik olarak kullanıcıyı sistemden atacak.
                        signInManager.SignOutAsync();
                        signInManager.PasswordSignInAsync(user, passwordChangeViewModel.PasswordNew, true, false);

                            ViewBag.success = "true";
                        }
                        else
                        {
                        AddModelError(result);
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Eski şifreniz yanlış.");
                    }
            }


            return View(passwordChangeViewModel);
        }

        public void LogOut()
        {
            signInManager.SignOutAsync();
        }

        public IActionResult AccessDenied(string returnUrl)
        {
            if (returnUrl.Contains("ViolencePage")){
                ViewBag.message = "Erişmeye çalıştığınız sayfa şiddet videoları içerdiğinden dolayı , 15 yaşından büyük olmanız gerekmektedir.";
            }
            else if (returnUrl.Contains("IstanbulPage")){
                ViewBag.message = "Bu sayfaya sadece şehir alanı İstanbul olan kullanıcılar erişebilr.";
            }
            else if (returnUrl.Contains("Exchange"))
            {
                ViewBag.message = "30 günlük ücretsiz deneme hakkınız sona ermiştir.";
            }
            else
            {
                ViewBag.message = "Bu satfaya erişim izniniz yoktur. Erişim izni almak için site yöneticisi ile görüşünüz.";
            }
       
            return View();
        }

        [Authorize(Roles = "Editor")]
        public IActionResult Editor()
        {
            return View();
        }

        [Authorize(Roles = "Manager")]
        public IActionResult Manager()
        {
            return View();
        }

        [Authorize(Policy = "IstanbulPolicy")]
        public IActionResult IstanbulPage()
        {

            return View();
        }

        [Authorize(Policy = "ViolencePolicy")]
        public IActionResult ViolencePage()
        {

            return View();
        }

        public async Task<IActionResult> ExchangeRedirect()
        {
            bool result = User.HasClaim(x => x.Type == "ExpireDateExchange");

            if (!result)
            {
                Claim ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).Date.ToShortDateString(), ClaimValueTypes.String, "Interna");

                await userManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await signInManager.SignOutAsync();
                await signInManager.SignInAsync(CurrentUser, true);
            }

            return RedirectToAction("Exchange");
        }

        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }
    }
}
