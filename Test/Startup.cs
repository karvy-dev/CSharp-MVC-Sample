using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(UI_Test.Startup))]
namespace UI_Test
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
