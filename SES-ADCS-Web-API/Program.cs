using Carter;
using NLog;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Topshelf;

class Program : ServiceControl
{
    private BackgroundWorker thread;
    private WebApplication? app;
    private static readonly Logger logger = LogManager.GetLogger(" Service");

    static void Main(string[] args)
    {
        var service = HostFactory.New(x =>
        {
            x.SetServiceName("SES_ADCS_Web_API");
            x.SetDisplayName("SES ADCS Web API");
            x.SetDescription("SES PKI - Web API for ADCS");
            x.Service<Program>();
        });
        service.Run();
    }

    public bool Start(HostControl hostControl)
    {
        thread = new BackgroundWorker();
        thread.DoWork += RunMain;
        thread.RunWorkerAsync();
        logger.Info("SES ADCS Web API service started.");        
        return true;
    }

    private void RunMain(object? sender, DoWorkEventArgs e)
    {
        var builder = WebApplication.CreateBuilder();

        string certThumbprint = builder.Configuration["Kestrel:Certificates:Default:Thumbprint"];
        int port = int.Parse(builder.Configuration["Kestrel:Certificates:Default:Port"]);

        logger.Info("Starting web server.");
        builder.WebHost.ConfigureKestrel(serverOptions =>
        {
            serverOptions.AllowSynchronousIO = true;
        });

        // Configure Kestrel to use HTTPS with the certificate from the Local Machine store
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(port, listenOptions =>
            {
                listenOptions.UseHttps(httpsOptions =>
                {
                    httpsOptions.ServerCertificateSelector = (context, name) =>
                    {
                        // Find the certificate in the Local Machine store
                        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                        store.Open(OpenFlags.ReadOnly);
                        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, validOnly: false);

                        // Use the first certificate found (ensure there’s only one or filter specifically)
                        return certs.Count > 0 ? certs[0] : null;
                    };
                });
            });
        });
        builder.Services.AddCarter();

        app = builder.Build();

        //app.MapGet("/", () => "Hello World!");

        app.MapCarter();

        app.Run();

        logger.Info($"Web server started. Listening on port: {port} with HTTPS certificate thumbprint: {certThumbprint}");
    }

    public bool Stop(HostControl hostControl)
    {
        logger.Info("Stopping web server.");
        app?.StopAsync();
        logger.Info("SES ADCS Web API service is stopping.");
        return true;
    }
}