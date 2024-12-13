# -*- coding: utf-8 -*-
""" skeleton for customized CA handler """
from __future__ import print_function
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, csr_cn_get
import requests
import json
import random
import string
import time
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.parameter = None
        self.ca_bundle = False

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.parameter:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic and 'parameter' in config_dic['CAhandler']:
            self.parameter = config_dic['CAhandler']['parameter']
        if 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        self.logger.debug('CAhandler._config_load() ended')

    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))

        self.logger.debug('CAhandler._stub_func() ended')

    def _file_load(self, bundle):
        """ load file """
        file_ = None
        try:
            with open(bundle, 'r', encoding='utf-8') as fso:
                file_ = fso.read()
        except Exception as err_:
            self.logger.error('CAhandler._file_load(): could not load {0}. Error: {1}'.format(bundle, err_))
        return file_

    def _clean_csr(self, csr):
        # Split the CSR into lines and remove the BEGIN/END lines
        lines = csr.split('\n')
        clean_lines = [line for line in lines if line.strip() and not line.startswith('-----BEGIN') and not line.startswith('-----END')]
        # Join the remaining lines without newlines
        return ''.join(clean_lines)

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None
        self._stub_func(csr)

        self.logger.debug('Certificate.enroll() ended')

        cn = csr_cn_get(self.logger, csr)
        csr_encoded = csr.replace('\n', '\\n')
        #seat_id = generate_seat_id()

        #url = "http://172.22.1.11:4080/api/certificates/enroll"
        url = "https://cwmsica01.cwlabs.xyz:8443/api/cert/enroll"
        # Load the private key from a file
        private_key_path = "/var/www/acme2certifier/acme_srv/private-key.pem"
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Define the data to sign (can be any string that the server expects to verify authenticity)
        #data_to_sign = "string"  # Replace with the specific data the server expects to validate

        # Get the current time in UTC as epoch time (in seconds)
        epoch_time = int(time.time())

        # Convert the epoch time to a string
        data_to_sign = str(epoch_time)

        # Sign the data
        data_to_sign_bytes = data_to_sign.encode("utf-8")
        signed_data = private_key.sign(
            data_to_sign_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Encode the signed data in Base64 for the API
        signed_data_base64 = base64.b64encode(signed_data).decode("utf-8")

        # Load the client certificate and retrieve its thumbprint
        cert_path = "/var/www/acme2certifier/acme_srv/signingCert.pem"
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()

        # Parse the certificate using cryptography
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Export certificate in DER format using serialization.Encoding.DER
        der_cert_data = cert.public_bytes(serialization.Encoding.DER)

        # Calculate the SHA-1 hash (thumbprint) of the DER-encoded certificate
        cert_thumbprint = hashlib.sha1(der_cert_data).hexdigest().upper()
        # Calculate the thumbprint (SHA-1) of the certificate
        #cert_thumbprint = hashlib.sha1(cert_data).hexdigest().upper()

        # Create the JSON payload for the request
        payload = json.dumps({
            "csr": csr,
            "includeChain": False,
            "dataToSign": data_to_sign,
            "signedData": signed_data_base64,
            "certThumbprint": cert_thumbprint
        })


        #payload = json.dumps({
          #"csr": csr_encoded,
          #"includeChain": False
        #})
        headers = {
          'accept': 'application/json',
          'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload)

        print(response.text)
        if response.status_code == 200:
            response_data = json.loads(response.text)
        else:
            self.logger.error('ERROR WHILE ENROLLING FOR A CERT:{0}'.format(response.text))
            #raise SystemException(f"CA HANDLER ENROLL: Failed to enroll for a certificate")
            error="ENROLL ERROR"
            return (error, None, None, None)

        # Parse the JSON response
        #response_data = json.loads(response.text)

        # Extract the certificate and replace '\\n' with actual newlines
        cert_nln = response_data['certificate']
        certificate_text = response_data['certificate'].replace('\\n', '\n')

        # Now you can work with the parsed data
        #serial_number = response_data['serial_number']
        #delivery_format = response_data['delivery_format']

        # Print the formatted certificate
        print("Certificate:")
        print(certificate_text)

        #cert_raw = certificate_text
        #cert_raw = cert_nln
        cert_raw = self._clean_csr(certificate_text)
        ca_pem = self._file_load(self.ca_bundle)
        cert_bundle = certificate_text + ca_pem
        #cert_bundle = cert_raw
        print(cert_bundle)

        #return (error, cert_bundle, cert_raw, poll_indentifier)
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, certificate_text, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)