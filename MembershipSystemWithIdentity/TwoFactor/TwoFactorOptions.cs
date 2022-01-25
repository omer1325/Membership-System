using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MembershipSystemWithIdentity.Service
{
    public class TwoFactorOptions
    {
        public string SendGrid_ApiKey { get; set; }
        public int CodeTimeExpire { get; set; }

        public string ACCOUNT_SID { get; set; }
        public string AUTH_TOKEN { get; set; }
    }
}
