#pragma checksum "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\Member\AccessDenied.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "5b30f86fd1b403d33543162283d21aa63de50abd"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Member_AccessDenied), @"mvc.1.0.view", @"/Views/Member/AccessDenied.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 3 "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\_ViewImports.cshtml"
using MembershipSystemWithIdentity.Models;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\_ViewImports.cshtml"
using MembershipSystemWithIdentity.ViewModels;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\_ViewImports.cshtml"
using MembershipSystemWithIdentity.Enums;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"5b30f86fd1b403d33543162283d21aa63de50abd", @"/Views/Member/AccessDenied.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"e0381a20564b5d42a77c6d30c5f40b8c32f2860f", @"/Views/_ViewImports.cshtml")]
    public class Views_Member_AccessDenied : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 2 "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\Member\AccessDenied.cshtml"
  
    ViewData["Title"] = "AccessDenied";
    Layout = "~/Views/Member/_MemberLayout.cshtml";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n<div class=\"alert alert-danger\">\r\n    ");
#nullable restore
#line 8 "C:\Users\omer\source\repos\MembershipSystemWithIdentity\MembershipSystemWithIdentity\Views\Member\AccessDenied.cshtml"
Write(ViewBag.message);

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
