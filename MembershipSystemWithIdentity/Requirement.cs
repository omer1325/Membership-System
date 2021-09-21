using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity
{
    //Buranın gövdesini boş bırakıyoruz. "ExpireDateExchangeRequirement" bu ismi startup kısmında kısıtlama ismi olarak kullanacağız.
    public class ExpireDateExchangeRequirement:IAuthorizationRequirement
    {
    }

    public class ExpireDateExchangeHandler : AuthorizationHandler<ExpireDateExchangeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ExpireDateExchangeRequirement requirement)
        {
            if (context.User != null & context.User.Identity != null)
            {
                var claim = context.User.Claims.Where(x => x.Type == "ExpireDateExchange" && x.Value != null).FirstOrDefault();

                if (claim != null)
                {
                    if (DateTime.Now < Convert.ToDateTime(claim.Value))
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        context.Fail();
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
