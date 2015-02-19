#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Signed SOAP webservices
"""

import urllib2 as u2
from suds.client import Client
from suds.wsse import *
from suds.transport.http import HttpTransport, Reply, TransportError
import httplib
from suds.xsd.doctor import ImportDoctor, Import
import logging


# Bash way to get PEM files out of a .p12 certificate:
# ----------
# Extract the key:
# openssl pkcs12 -nocerts -in ClientCert.p12 -out key.pem

# Extract the certificate:
# openssl pkcs12 -clcerts -nokeys -in ClientCert.p12 -out cert.pem

# You may also want to remove the passphrase from the key:
# openssl rsa -in key.pem -out key_nopass.pem


class HTTPSClientAuthHandler(u2.HTTPSHandler):
    def __init__(self, key, cert):
        u2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert
        print "> a"

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        print "> b"
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        print "> c"
        return httplib.HTTPSConnection(host, key_file=self.key,
                                       cert_file=self.cert)

class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, key, cert, proxy_settings=None, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert
        self.proxy_settings = proxy_settings
        print "> c"

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        print "> d"
        tm = self.options.timeout

        https_client_auth_handler = HTTPSClientAuthHandler(self.key,
                                                           self.cert)

        # Add a proxy handler if the proxy settings is specified.
        # Otherwise, just use the HTTPSClientAuthHandler.
        if self.proxy_settings:
            proxy_handler = u2.ProxyHandler(self.proxy_settings)
            url = u2.build_opener(proxy_handler, https_client_auth_handler)
        else:
            url = u2.build_opener(https_client_auth_handler)

        url = u2.build_opener()

        print ('> e. url: {}'.format(url))

        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)

# Test #
if __name__ == '__main__':
    # Namespaces:
    WSSE_URI = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    WSU_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    XMLDSIG_URI = "http://www.w3.org/2000/09/xmldsig#"
    X509v3_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    Base64Binary_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

    #xmlns_ds = "http://www.w3.org/2000/09/xmldsig#"
    #xmlns_xs = "http://www.w3.org/2001/XMLSchema"
    #xmlns = "http://www.facturae.es/Facturae/2014/v3.2.1/Facturae"
    #targetNamespace = "http://www.facturae.es/Facturae/2014/v3.2.1/Facturae"
    #version = "3.2.1"
    #namespace = "http://www.w3.org/2000/09/xmldsig#"
    #schemaLocation = "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd"

    # Extracted from: https://se-face-webservice.redsara.es/sspp?wsdl
    xmlns = "http://schemas.xmlsoap.org/wsdl/"
    xmlns_wsdl = "http://schemas.xmlsoap.org/wsdl/"
    xmlns_tns = "https://webservice.face.gob.es"
    xmlns_soap = "http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns_xsd = "http://www.w3.org/2001/XMLSchema"
    xmlns_soap_enc = "http://schemas.xmlsoap.org/soap/encoding/"
    xmlns_soap12 = "http://schemas.xmlsoap.org/wsdl/soap12/"
    name = "SSPPWebServiceProxy"
    

    url_staging = 'https://se-face-webservice.redsara.es/sspp?wsdl'
    ws_url = url_staging

    targetNamespace = "https://webservice.face.gob.es"
    tns = targetNamespace
    #tns = xmlns_tns

    logging.basicConfig(level=logging.INFO)
    logging.getLogger('suds.client').setLevel(logging.DEBUG)

    # ------------------------------------------------------------------------
    # Conexión simple, no cifrada:
    #print '> > > Conexión simple, no cifrada'
    
    ##imp = Import('http://schemas.xmlsoap.org/soap/encoding/',
                 ##'http://schemas.xmlsoap.org/soap/encoding/')
    #imp = Import(xmlns_soap_enc,
                 #location=xmlns_soap_enc)
    #imp.filter.add(tns)

    #doctor = ImportDoctor(imp)
    #client = Client(ws_url, doctor=doctor)
    ##client = Client(ws_url, plugins=[ImportDoctor(imp)])
    #print '> > >\n', client

    ##result = client.service.consultarAdministraciones()
    ##print '> > >\n', result
    ### This raises this error:
    ### suds.WebFault: Server raised fault: '1492762068441858 - 104 - SOAP Request Signature is not valid'

    print "-"*80
    # ------------------------------------------------------------------------
    # Conexión cifrada
    print '>>>>> Conexión cifrada con key+cert'
    # key= r'key_nopass.pem'
    #key = r'key.pem'
    #cert = r'cert.pem'
    key_file = 'key.pem'
    cert_file = 'cert.pem'
    response_key_staging = 'response_staging.pem'
    response_key_production = 'response_production.pem'
    response_key = response_key_staging
    
    key = None
    cert = None
    cert_p12_file = 'anubia_cad20160910.p12'
    
    with open(key_file, 'r') as f:
        key = f.read()
        #print ('->  KEY:\n\n{}\n\n'.format(key))

    with open(cert_file, 'r') as f:
        cert = f.read()
        #print ('>>   CERT:\n\n{}\n\n'.format(cert))

    #key = key_file
    #cert = cert_file
    
    # proxy_settings = {'https': 'http://user:password@host:port'}
    # transport = HTTPSClientCertTransport(key, cert, proxy_settings)
    #transport = HTTPSClientCertTransport(key, cert)
    transport = HTTPSClientCertTransport(key_file, cert_file)

    #client = Client(ws_url, transport=transport)
    #imp = Import('http://schemas.xmlsoap.org/soap/encoding/',
                 #'http://schemas.xmlsoap.org/soap/encoding/')
    imp = Import(xmlns_soap_enc,
                 location=xmlns_soap_enc)
    imp.filter.add(tns)
    doctor = ImportDoctor(imp)
    #client = Client(ws_url, plugins=[ImportDoctor(imp)])
    #client = Client(ws_url, doctor=doctor)
    
    security = Security()
    #token = UsernameToken('myusername', 'mypassword')
    #security.tokens.append(token)
    security.keys.extend(key_file)
    #security.keys.extend(response_key)
    
    #security.signatures.extend(cert_p12_file)
    #client.set_options(wsse=security)
    
    
    
    print '>>>>> Creating client...'
    #client = Client(ws_url, doctor=doctor, transport=transport)
    client = Client(ws_url, doctor=doctor, transport=transport, wsse=security)
    print '>>>>>\n', client

    # Methods (8):
        # anularFactura(xs:string numeroRegistro, xs:string motivo, )
        # consultarAdministraciones()
        # consultarEstados()
        # consultarFactura(xs:string numeroRegistro, )
        # consultarListadoFacturas(ns0:Array listadoFacturas, )
        # consultarUnidades()
        # consultarUnidadesPorAdministracion(xs:string codigoDir, )
        # enviarFactura(SSPPFactura facturaWS, )
    try:
        result = client.service.consultarUnidades()
        print '\n\n>>>>>\n', result
        result = client.service.consultarAdministraciones(token=token)
        print '\n\n>>>>>\n', result
    except WebFault, err:
        print unicode(err)

