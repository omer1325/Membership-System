using MembershipSystemWithIdentity.Models;
using MembershipSystemWithIdentity.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Controllers
{
    public class HomeController : BaseController
    {
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base(userManager, signInManager)
        {
        }
        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }

            return View();
        }

        public IActionResult LogIn(string ReturnUrl)
        {
            TempData["ReturnUrl"] = ReturnUrl;

            return View();
        }   

        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel userLogin)
        {
            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(userLogin.Email);
                if (user != null)
                {
                    //Kullanıcının kilitli olup olmadığına bakıyoruz. Eğer True dönerse hata mesajı patlatıyoruz.
                    if (await userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınız bir süreliğine kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");

                        return View(userLogin);
                    }

                    if (userManager.IsEmailConfirmedAsync(user).Result == false)
                    {
                        ModelState.AddModelError("", "Email adresiniz onaylanmamıştır. Lütfen e-postanızı kontrol ediniz.");
                        return View(userLogin);
                    }


                    //Kullanıcı hakkında Cookie var ise siler, çünkü kullanıcı tekrardan login oluyor.
                    await signInManager.SignOutAsync();
                    //RememberMe eğer işaretlenmediye False olacak, işaretlendiyse True olacak. Bu sayede Cookieleri tutabileceğiz.
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user,
                        userLogin.Password, userLogin.RememberMe, false);

                    if (result.Succeeded)
                    {
                        //Kullanıcının başarısız giriş denemelerini sıfırlar.
                        await userManager.ResetAccessFailedCountAsync(user);


                        if (TempData["ReturnUrl"] != null)
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }
                        return RedirectToAction("Index", "Member");
                    }
                    else
                    {
                        //Kullanıcının başarısız giriş sayısını bir arttıracak.
                        await userManager.AccessFailedAsync(user);

                        int fail = await userManager.GetAccessFailedCountAsync(user);
                        ModelState.AddModelError("", $"{fail} kez başarısız giriş yaptınız.");
                        if (fail == 3)
                        {
                            // Eğer başarısız giriş sayısı 3 tane ise, kullanıcıyı 20 dakika kilitliyor.
                            await userManager.SetLockoutEndDateAsync(user, new DateTimeOffset(DateTime.Now.AddMinutes(20)));

                            ModelState.AddModelError("", "Hesabınız 3 başarısız girişten dolayı 20 dakika süreyle kilitlenmiştir. " +
                                "Lütfen daha sonra tekrar deneyiniz.");
                        }
                        else
                        {
                            ModelState.AddModelError("", "Email adresiniz veya şifreniz yanlıştır.");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Bu email adresine ait kayıtlı kullanıcı bulunamamıştır.");
                }
            }

            return View(userLogin);
        }

        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {
            if (ModelState.IsValid)
            {
                //userManager.Users ile bütün kayıtlı kullanıcılara erişiyoruz.
                //Any ile database'de sorgumuz oluğ olmadığını kontrol ediyor. Any'den True veya False döner.
                if (userManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu telefon numarası kayıtlıdır.");
                    return View(userViewModel);
                }


                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;

                //Password kısmını burada vermemizin amacı Passwordu text şeklinde değilde şifreli şeklince DataBase'e kaydetmesidir.
                IdentityResult result = await userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    //Email doğruamak için token ve link oluşturuyoruz.
                    string confirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
                    string link = Url.Action("ConfirmEmail", "Home", new
                    {
                        userId = user.Id,
                        token = confirmationToken
                    }, protocol: HttpContext.Request.Scheme
                    );

                    Helper.EmailConfirmation.SendEmail(link, user.Email);

                    return RedirectToAction("LogIn");
                }
                else
                {
                    AddModelError(result);
                }

            }
            return View(userViewModel);
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            AppUser user = userManager.FindByEmailAsync(passwordResetViewModel.Email).Result;
            if (user != null)
            {
                string passwordResetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;


                //Link oluşturma
                //www.bıdıbıdı.com/Home/ResetPasswordConfirm?userId=asdajgfdskjfka&token=ahkjafgdskj

                string passwordResetLink = Url.Action("ResetPasswordConfirm", "Home", new
                {
                    userId = user.Id,
                    token = passwordResetToken,
                },HttpContext.Request.Scheme);

                Helper.PasswordReset.PasswordResetSendEmail(passwordResetLink, user.Email);
                ViewBag.status = "success";
                //TempData["durum"] = true.ToString();
            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı bir email adresi bulunamamıştır.");
            }

            return View(passwordResetViewModel);
        }

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;
            return View();
        }

        //Bind ile PasswordResetViewModel sınıfından sadece belirttiğimiz property gelicek 
        [HttpPost]
        public async Task<IActionResult> ResetPasswordConfirm([Bind("PasswordNew")]PasswordResetViewModel passwordResetViewModel)
        {
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            AppUser user = await userManager.FindByIdAsync(userId);
            if (user != null)
            {
                IdentityResult result = await userManager.ResetPasswordAsync(user, token, passwordResetViewModel.PasswordNew);

                if (result.Succeeded)
                {
                    await userManager.UpdateSecurityStampAsync(user);

                    ViewBag.status = "success";
                }
                else
                {
                    AddModelError(result);
                }
            }

            else
            {
                ModelState.AddModelError("", "Bir hata meydana geldi. Lütfen daha sonra tekrar deneyiniz.");
            }


            return View(passwordResetViewModel);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);
            IdentityResult result = await userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                ViewBag.status = "Email adresiniz onaylanmıştır. Login ekranından giriş yapabilirsiniz.";
            }
            else
            {
                ViewBag.status = "Bir hata meydana geldi. Lütfen daha sonra tekrar deneyiniz.";
            }

            return View();
        }

        public IActionResult FacebookLogIn(string ReturnUrl)
        {
            //Kullanıcını Facebook'ta işlemleri bittikten sonra gelecek olan URL.
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            //Burada hangi sosal  medya ile bağlanmaya çalışıyorsak onun ismini yazıyoruz. Daha sonra döneceği adresi yazıyoruz.
            //Facebooktan başarılı sonuç geldiğinde verdiğimiz sayfaya dönecek
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);
            //Burada kullanıcıyı Facebook'a yönlendiriyoruz. 
            return new ChallengeResult("Facebook", properties);
        }

        public IActionResult GoogleLogIn(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);
            return new ChallengeResult("Google", properties);
        }

        public IActionResult MicrosoftLogIn(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);
            return new ChallengeResult("Microsoft", properties);
        }

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            //Kullanıcın login olduğu ile ilgili bilgiler vericek.
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("LogIn");
            }
            else
            {
                //Login işlemi gerçekleştiriyoruz. Eğer veri tabanında kullanıcı login olmuşsa, kullanıcıya izin vericek ama değerler yoksa verileri kaydetmemiz lazım.
                Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                if (result.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                else
                {
                    AppUser user = new AppUser();

                    //Kullanın email bilgisi,Facebook tarafından gelen Claimden alacağız.
                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    //Kullanıcının Facebook'taki Id'sini alıyoruz.
                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                    //Kullanıcın adını ve soyadını alıyoruz. Daha sonra Guid değer atıyoruz.
                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;

                        userName = userName.Replace(' ', '-').ToLower() + ExternalUserId.Substring(0, 5).ToString();

                        user.UserName = userName;
                    }
                    else
                    {
                        //Eğer kullanıcın ismini alamazsak, kullanaıcın User Name kısmını e-Mail adresi yapıyoruz.
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }


                    //Kullanıcı daha önce sosyal medra araçları ile sisteme kayıtlı olmadıysa burada sisteme kayıt ediyoruz.
                    AppUser user2 = await userManager.FindByEmailAsync(user.Email);
                    if (user2 == null)
                    {
                        //Kullanıcıyı Database'e kaydediyoruz.
                        IdentityResult createResult = await userManager.CreateAsync(user);

                        if (createResult.Succeeded)
                        {
                            //Burada bilgileri database kısmına ekliyoruz.
                            IdentityResult loginResult = await userManager.AddLoginAsync(user, info);
                            //Burada sisteme giriş işlemi yapıyoruz.
                            if (loginResult.Succeeded)
                            {
                                //await signInManager.SignInAsync(user, true);
                                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                                return Redirect(ReturnUrl);
                            }
                            else
                            {
                                AddModelError(loginResult);
                            }
                        }
                        else
                        {
                            AddModelError(createResult);
                        }
                    }
                    //Burada eğer kullanıcı başka bir sosyal medya aracı ile giriş yaptıysa, kullanıcıyı tekrardan sisteme kayıt yapmıyoruz,
                    //sadece nereden geldiği bilgisini kayıt ediyoruz.
                    else
                    {
                        IdentityResult loginResult = await userManager.AddLoginAsync(user2, info);
                        await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                        return Redirect(ReturnUrl);
                    }
                }
            }
            //SelectMany ile ModelState.Values'den gelen hataları yakalıyoruz. Select ile hatalrı List<string> içine atıyoruz.
            List<string> errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();

            return View("Error", errors);
        }

        public ActionResult Error()
        {
            return View();
        }
    }
}
