using Sitecore.Abstractions;
using Sitecore.Pipelines.GetSignInUrlInfo;
using System.Web.Mvc;

namespace Sitecore.Feature.SSO.Controllers
{
    public class SSOController : Controller
    {
        public ActionResult Index()
        {
            var url = "/";
            if (!string.IsNullOrEmpty(Request.QueryString?["item"]))
            {
                url = Request.QueryString["item"];
            }

            var codePipelineManager = DependencyResolver.Current.GetService<BaseCorePipelineManager>();
            var args = new GetSignInUrlInfoArgs("website", url);
            GetSignInUrlInfoPipeline.Run(codePipelineManager, args);

            return View("/Views/SSO/Login.cshtml", args.Result);
        }
    }
}