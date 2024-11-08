using Carter;
using NLog;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SES_ADCS_Web_API
{

    public class CertEnrollmentModule : ICarterModule
    {
        private static readonly Logger logger = LogManager.GetLogger(" WebAPI ");
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/cert/enroll", async (HttpRequest req, HttpResponse res) =>
            {
                CertEnrollRequest request = new();
                logger.Debug($"\"Received request from IP: {req.HttpContext.Connection.RemoteIpAddress}");
                
                // Read the request body asynchronously
                using var reader = new StreamReader(req.Body);
                foreach (var header in req.Headers)
                {
                    logger.Debug("Header {Header}: {Value}", header.Key, header.Value);
                }
                var bodyString = await reader.ReadToEndAsync();
                
                try
                {
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    };

                    // Deserialize the JSON body to the CertEnrollRequest model
                    request = JsonSerializer.Deserialize<CertEnrollRequest>(bodyString, options);
                    logger.Info("Certificate Enrollment Request received with Thumbprint: {Thumbprint}, DataToSign: {DataToSign}", request.CertThumbprint, request.DataToSign);
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Error deserializing the request body");
                    res.StatusCode = StatusCodes.Status400BadRequest;
                    await res.WriteAsync("Error reading the JSON body");
                    return;
                }
                // Step 1: Validate the signature
                var validationMessage = ValidateSignature(request.DataToSign, request.SignedData, request.CertThumbprint);
                if (validationMessage != "Valid")
                {
                    logger.Warn("Invalid signature: {ValidationMessage}", validationMessage);
                    res.StatusCode = StatusCodes.Status401Unauthorized;
                    await res.WriteAsync(validationMessage);
                    return;
                }

                try
                {
                    // Decode CSR
                    byte[] csrBytes = Convert.FromBase64String(request.Csr);                    

                    //Enroll certificate from ADCS
                    var certResponse = ADCS.IssueCertificate(request.Csr);
                    var certificate = new X509Certificate2(Convert.FromBase64String(certResponse));

                    // Get certificate chain if requested
                    if (request.IncludeChain)
                    {
                        var chain = GetCertificateChain(certificate);
                        var chainBase64 = Convert.ToBase64String(chain);
                        var responseObj = new { certificate = chainBase64 };
                        res.StatusCode = StatusCodes.Status200OK;
                        await res.WriteAsJsonAsync(responseObj);
                        return;
                    }

                    // Format certificate with line breaks
                    var certBase64 = Convert.ToBase64String(certificate.RawData);
                    var formattedCert = $"-----BEGIN CERTIFICATE-----\n{InsertLineBreaks(certBase64, 64)}\n-----END CERTIFICATE-----\n";

                    var finalResponse = new { certificate = formattedCert };
                    res.StatusCode = StatusCodes.Status200OK;
                    await res.WriteAsJsonAsync(finalResponse);
                }
                catch (Exception ex)
                {
                    logger.Error("Error enrolling certificate");
                    logger.Error(ex.ToString());
                    res.StatusCode = StatusCodes.Status500InternalServerError;
                    await res.WriteAsync($"Error enrolling certificate: {ex.Message}");
                }
            });
        }

        private string ValidateSignature(string dataToSign, string signedDataBase64, string certThumbprint)
        {
            // Convert dataToSign to an integer timestamp (epoch time) and get the current UTC timestamp
            if (!long.TryParse(dataToSign, out long clientEpochTime))
            {
                return "Invalid dataToSign format, expected epoch timestamp.";
            }

            long serverEpochTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Check if the timestamp is within a ±1 minute range (60 seconds)
            if (Math.Abs(serverEpochTime - clientEpochTime) > 60)
            {
                return "Timestamp outside allowed range.";
            }
            // Find the certificate in the Trusted People store
            using (var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, false);

                if (certCollection.Count == 0)
                {
                    return "Certificate not found in Trusted People store";
                }

                var cert = certCollection[0];
                using (var rsa = cert.GetRSAPublicKey())
                {
                    if (rsa == null)
                    {
                        return "Certificate does not have an RSA public key";
                    }

                    // Convert dataToSign and signedData for verification
                    byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);
                    byte[] signedDataBytes = Convert.FromBase64String(signedDataBase64);

                    // Verify the signature
                    bool isValid = rsa.VerifyData(dataBytes, signedDataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    if (isValid)
                    {
                        logger.Info($"API request authenticated successfully. Cert thumbprint: {certThumbprint}, subject: {cert.Subject}");
                    }
                    else
                    {
                        return "Invalid signature";
                    }

                }
            }
            
            return "Valid";
        }

        private static string InsertLineBreaks(string input, int lineLength)
        {
            if (string.IsNullOrEmpty(input) || lineLength <= 0)
                return input;

            var result = new System.Text.StringBuilder();
            for (int i = 0; i < input.Length; i += lineLength)
            {
                result.Append(input.AsSpan(i, Math.Min(lineLength, input.Length - i)));
                // Only add a newline if this isn't the last line
                if (i + lineLength < input.Length)
                {
                    result.Append('\n');
                }
            }

            return result.ToString();
        }


        private static byte[] GetCertificateChain(X509Certificate2 cert)
        {
            // Build certificate chain
            var chain = new X509Chain();
            chain.Build(cert);
            List<byte> chainBytes = new List<byte>();

            foreach (var element in chain.ChainElements)
            {
                chainBytes.AddRange(element.Certificate.RawData);
            }

            return [.. chainBytes];
        }

        // Define the request model
    }

    public class CertEnrollRequest
    {
        public string? Csr { get; set; }
        public bool IncludeChain { get; set; }
        public string? DataToSign { get; set; }
        public string? SignedData { get; set; }
        public string? CertThumbprint { get; set; }
    }

}