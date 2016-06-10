using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Debcenter.Startup))]
namespace Debcenter
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
