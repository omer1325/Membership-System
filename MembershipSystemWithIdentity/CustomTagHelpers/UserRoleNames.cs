using MembershipSystemWithIdentity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Razor.TagHelpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.CustomTagHelpers
{
    //Html dosyamızdaki user-role parametresini yakalıyoruz.
    [HtmlTargetElement("td", Attributes = "user-roles")]
    public class UserRoleNames:TagHelper
    {
        public UserManager<AppUser> userManager { get; set; }

        public UserRoleNames(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }


        //Oluşturduğumuz UserId propertisinin içine HTML sayfasındaki "user-roles" içinde olan ID'yi verir.
        [HtmlAttributeName("user-roles")]
        public string UserId { get; set; }

        //Bu method, yazdığımız html ifadeyi yakaladığımız td'nin içine basar. Basarken output olarak yollar.
        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            AppUser user = await userManager.FindByIdAsync(UserId);

            IList<string> roles =  await userManager.GetRolesAsync(user);

            string html = string.Empty;

            roles.ToList().ForEach(x =>
            {
                html += $"&emsp;<span class='btn btn-info'> {x} </span>";
            });

            output.Content.SetHtmlContent(html);
        }
    }
}
