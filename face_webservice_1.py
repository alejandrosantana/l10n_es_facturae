#!/usr/bin/env python2
# -*- coding: utf-8 -*-

'''
Schemas URLs:
- Esquema XSD formato Facturae v3.2.1 [XML]:
  http://www.facturae.gob.es/formato/ultimaversion/A)%20Versi%C3%B3n%203.2.1/Facturaev3_2_1.xml
- Esquema XSD formato Facturae v3.2 [XML]:
  http://www.facturae.gob.es/formato/ultimaversion/B)%20Versi%C3%B3n%203.2/Facturaev3_2.xml
'''

from lxml import etree
from io import StringIO, BytesIO

from suds.client import Client
from suds.xsd.doctor import Import
from suds.xsd.doctor import ImportDoctor


# ********************************************************
import urllib2, httplib, socket
from suds.client import Client
from suds.transport.http import HttpTransport, Reply, TransportError

class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(host,
                                       key_file=self.key,
                                       cert_file=self.cert)

class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, key, cert, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        url = urllib2.build_opener(HTTPSClientAuthHandler(self.key, self.cert))
        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)

# These lines enable debug logging; remove them once everything works.
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger('suds.client').setLevel(logging.DEBUG)
logging.getLogger('suds.transport').setLevel(logging.DEBUG)

c = Client('https://se-face-webservice.redsara.es/sspp?wsdl',
           transport=HTTPSClientCertTransport('anubia_cad20160910.p12',
                                              'anubia_cad20160910.pem'))
print c

# ********************************************************
## Para la validación de la firma: Portal @firma:
# http://administracionelectronica.gob.es/ctt/afirma

class FACeWebServices():
    xml_schemas = {
        'xmlns_ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xmlns_fe': 'http://www.facturae.es/Facturae/2009/v3.2/Facturae',
    }
    url_staging = 'https://se-face-webservice.redsara.es/sspp?wsdl'
    # url_prod = 'https://webservice.face.gob.es/sspp?wsdl'
    url = url_staging

    xmlns_xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xmlns_xsd = 'http://www.w3.org/2001/XMLSchema'
    xmlns_soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xmlns_web = 'https://webservice.face.gob.es'
    'http://schemas.xmlsoap.org/soap/encoding/'
    https_protocols = 'TLSv1'

    mimes_allowed = ['image/jpeg',
                     'image/png',
                     'application/pdf',
                     'application/msword',
                     'application/msword',
                     'application/zip',
                     'application/x-rar-compressed',
                     'text/plain',
                     ]

    states = {
        '1200': {'name': 'Registrada',
                 'type': 'transaction',
                 'desc': ('La factura ha sido registrada en el registro '
                      'electrónico REC'),
                 },
        '1300': {'name': 'Registrada en RCF',
                 'type': 'transaction',
                 'desc': ('La factura ha sido registrada en el RCF'),
                 },
        '2400': {'name': 'Contabilizada la obligación de pago',
                 'type': 'transaction',
                 'desc': ('La factura ha sido reconocida con obligación de '
                          'pago'),
                 },
        '2500': {'name': 'Pagada',
                 'type': 'transaction',
                 'desc': 'Factura pagada',
                 },
        '2600': {'name': 'Rechazada',
                 'type': 'transaction',
                 'desc': 'Rechazada',
                 },
        '3100': {'name': 'Anulada',
                 'type': 'transaction',
                 'desc': 'La Unidad aprueba la propuesta de anulación',
                 },
        '4100': {'name': 'No solicitada anulación',
                 'type': 'cancelation',
                 'desc': 'No solicitada anulación',
                 },
        '4200': {'name': 'Solicitada anulación',
                 'type': 'cancelation',
                 'desc': 'Solicitada anulación',
                 },
        '4300': {'name': 'Aceptada anulación',
                 'type': 'cancelation',
                 'desc': 'Aceptada anulación',
                 },
        '4400': {'name': 'Solicitud de anulación',
                 'type': 'cancelation',
                 'desc': 'Rechazada anulación',
                 },
    }

    # Methods (8):
        # anularFactura(xs:string numeroRegistro, xs:string motivo, )
        # consultarAdministraciones()
        # consultarEstados()
        # consultarFactura(xs:string numeroRegistro, )
        # consultarListadoFacturas(ns0:Array listadoFacturas, )
        # consultarUnidades()
        # consultarUnidadesPorAdministracion(xs:string codigoDir, )
        # enviarFactura(SSPPFactura facturaWS, )

    # anularFactura(xs:string numeroRegistro, xs:string motivo, )
    def cancel_invoice(self, reg_num=None, reason=None):
        '''Este servicio permite solicitar la anulación de una factura.
        Es necesario que el cambio de estado sea válido. No se podrá solicitar
        la anulación de facturas en estado:
        Pagada, Rechazada, Anulada o Propuesta Anulación.
        
        Allows asking for an invoice cancel.
        State change must be possible. It will not be possible to cancel
        invoice in any of these states:
        paid, rejected, canceled, cancel proposal.'''
        pass

    # consultarAdministraciones()
    def get_administrations(self):
        '''Este servicio permite consultar las Administraciones'''
        pass

    # consultarEstados()
    def get_possible_states(self):
        '''Este servicio permite consultar los posibles estados de una factura.
        '''
        pass

    # consultarFactura(xs:string numeroRegistro, )
    def get_invoice_state(self, reg_num=None):
        '''Este servicio permite consultar el estado de una factura.
        
        Allows checking one invoice state.'''
        pass

    # consultarListadoFacturas(ns0:Array listadoFacturas, )
    def get_invoice_list(self, invoice_ids=None):
        '''Este servicio permite consultar el estado de varias factura.'''
        if invoice_ids is None:
            invoice_ids = []
            # return a warning telling no invoice was selected
        pass

    # consultarUnidades()
    def get_units(self):
        '''Este servicio permite consultar los organos gestores y unidades
        tramitadoras existentes en el sistema.'''
        pass

    # consultarUnidadesPorAdministracion(xs:string codigoDir, )
    def get_units_by_administration(self, code=None):
        '''Este servicio permite consultar los organos gestores, unidades
        tramitadoras y oficinas contables por administración.'''
        pass

    # enviarFactura(SSPPFactura facturaWS, )
    def send_invoice(self, invoice=None):
        '''Este servicio permite enviar facturas al sistema.
        
        Allows sending invoices to the system.'''
        pass


# ACTUAL EXECUTION
print("---------------------------------")
if __name__ == "__main__":
    face_ws = FACeWebServices()
    in_file = 'factura-prueba-v1-2-0.xml'
    xml_invoice = etree.parse(in_file)

    print xml_invoice

    #tns = 'https://webservice.face.gob.es'
    tns = 'https://se-face-webservice.redsara.es'
    imp = Import('http://schemas.xmlsoap.org/soap/encoding/',
                 'http://schemas.xmlsoap.org/soap/encoding/')
    imp.filter.add(tns)
    client = Client(face_ws.url, plugins=[ImportDoctor(imp)])
    print client

    result = client.service.consultarAdministraciones()
    print result

    
    