# Prerequisites
1. ADCS installed and running
2. .NET 8.0 runtime and ASP.NET runtime
3. verify the installation using `dotnet --version`

# Build
1. Clone the repo
2. `cd <repo_directory>`
3. Restore Dependencies
   `dotnet restore`
4. Build the Application
   `dotnet build`
5. Publish the Application
   `dotnet publish -c Release -o <PATH_TO_THE_APP>`
   
# Configure the environment
1. Edit `appsettings.json`
   - PfxPath
   - PfxPass
   - Port
   - CAConfig
   - TemplateName
2. Edit `NLog.config` file
   - fileName="<PATH_TO_LOG>/${shortdate}.log.txt"

# Install the service
1. Navigate to the published app
2. Run `SES-ADCS-Web-API.exe --install`
3. Go to Services, edit the SES ADCS Web API Service, Under Log On, use the appropriate service account
4. Restart the service
