using CERTCLILib;
using CERTENROLLLib;
using NLog;

namespace SES_ADCS_Web_API
{
    public static class ADCS
    {
        private static readonly Logger logger = LogManager.GetLogger(" Enroll ");
        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_CHAIN = 0x100;
        private const int CR_IN_MACHINE = 0x100000;

        public static string IssueCertificate(string csr)
        {
            var builder = WebApplication.CreateBuilder();
            string caConfig = builder.Configuration["ADCS_CA_DETAILS:CAConfig"];
            string caTemplateName = builder.Configuration["ADCS_CA_DETAILS:TemplateName"];
            string cert = "";
            logger.Info("Trying to parse the CSR");
            IX509CertificateRequestPkcs10 pkcs10 = (IX509CertificateRequestPkcs10)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));
            pkcs10.InitializeDecode(csr, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

            var nr = pkcs10.RawData;
            logger.Info("Parsed CSR Subject: {Subject}", pkcs10.Subject.Name);
            logger.Debug($"CSR Key Type: {pkcs10.PublicKey.Algorithm.FriendlyName}" );

            
            var objEnroll = new CX509Enrollment();
            logger.Info($"Sending certificate request to the ADCS CA: {caConfig} and template: {caTemplateName}");
            int reqID = SendCertificateRequest(csr, caConfig, caTemplateName);
            
            var objCertRequest = new CCertRequest();            
            var iDisposition = objCertRequest.RetrievePending(reqID, caConfig);
            if (iDisposition == CR_DISP_ISSUED)
            {
                cert = objCertRequest.GetCertificate(CR_OUT_BASE64);
            }
            else
            {
                logger.Warn($"Certificate has not been issued. Request ID: {reqID}");
            }            
            return cert;
        }
        private static int SendCertificateRequest(string message, string caConfig, string caTemplateName)

        {
            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.Submit(
            CR_IN_BASE64,
            message,
            $"CertificateTemplate:{caTemplateName}",
            caConfig);

            switch (iDisposition)
            {
                case CR_DISP_ISSUED:
                    logger.Info($"Certificate has been ISSUED from ADCS with request ID: {objCertRequest.GetRequestId()}");
                    break;
                case CR_DISP_UNDER_SUBMISSION:
                    logger.Info($"Certificate is UNDER SUBMISSION from ADCS with request ID: {objCertRequest.GetRequestId()}");
                    break;
                default:
                    logger.Info($"Certificate status from ADCS is UNKNOWN with request ID: {objCertRequest.GetRequestId()}");
                    break;
            }            
            return objCertRequest.GetRequestId();
        }
    }
}
