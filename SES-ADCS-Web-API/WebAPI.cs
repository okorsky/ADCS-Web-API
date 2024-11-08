using Carter;
using NLog;

namespace SES_ADCS_Web_API
{
    public class HomeModule : ICarterModule
    {
        private static Logger logger = LogManager.GetLogger(" Root   ");
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapGet("/", () => "Hello there ;)");
        }
    }
}
