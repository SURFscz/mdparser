from lxml import etree
from signxml import XMLVerifier, InvalidSignature
from datetime import datetime, timedelta
import iso8601
import pkg_resources
from cryptography import x509
from cryptography.hazmat.backends import default_backend

NS = dict(md="urn:oasis:names:tc:SAML:2.0:metadata",
          ds='http://www.w3.org/2000/09/xmldsig#',
          mdui="urn:oasis:names:tc:SAML:metadata:ui",
          mdattr="urn:oasis:names:tc:SAML:metadata:attribute",
          mdrpi="urn:oasis:names:tc:SAML:metadata:rpi",
          shibmd="urn:mace:shibboleth:metadata:1.0",
          xrd='http://docs.oasis-open.org/ns/xri/xrd-1.0',
          pyff='http://pyff.io/NS',
          xml='http://www.w3.org/XML/1998/namespace',
          saml="urn:oasis:names:tc:SAML:2.0:assertion",
          xs="http://www.w3.org/2001/XMLSchema",
          xsi="http://www.w3.org/2001/XMLSchema-instance",
          ser="http://eidas.europa.eu/metadata/servicelist")


class ResourceResolver(etree.Resolver):
  def __init__(self):
    super(ResourceResolver, self).__init__()

  def resolve(self, system_url, public_id, context):
    """
    Resolves URIs using the resource API
    """
    # log.debug("resolve SYSTEM URL' %s' for '%s'" % (system_url, public_id))
    path = system_url.split("/")
    fn = path[len(path) - 1]
    if pkg_resources.resource_exists(__name__, fn):
      return self.resolve_file(pkg_resources.resource_stream(__name__, fn), context)
    elif pkg_resources.resource_exists(__name__, "schema/%s" % fn):
      return self.resolve_file(pkg_resources.resource_stream(__name__, "schema/%s" % fn), context)
    else:
      raise ValueError("Unable to locate %s" % fn)


def iso2datetime(s):
  return iso8601.parse_date(s)


def schema():
  try:
    parser = etree.XMLParser(collect_ids=False, resolve_entities=False)
    parser.resolvers.add(ResourceResolver())
    st = etree.parse(pkg_resources.resource_stream(__name__, "schema/schema.xsd"), parser)
    schema = etree.XMLSchema(st)
  except etree.XMLSchemaParseError as ex:
    print(ex.error_log)
    raise ex

  return schema


def parse_xml(io):
  return etree.parse(io, parser=etree.XMLParser(resolve_entities=False, collect_ids=False))


def root(t):
  if hasattr(t, 'getroot') and hasattr(t.getroot, '__call__'):
    return t.getroot()
  else:
    return t


def validate_document(t):
  schema().assertValid(t)


def validate_signature(t):
  certs = t.iterfind('.//{%s}X509Certificate' % NS['ds'])
  valid = False
  exception = Exception
  for cert in certs:
    try:
      XMLVerifier().verify(t, x509_cert=cert.text).signed_xml
      valid = True
      break
    except InvalidSignature as e:
      exception = e
  if not valid:
    raise exception


def metadata_expiration(t):
  delta = timedelta(seconds=0)
  if t.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
    valid_until = t.get('validUntil', None)
    if valid_until is not None:
      now = datetime.utcnow()
      vu = iso2datetime(valid_until)
      now = now.replace(microsecond=0)
      vu = vu.replace(microsecond=0, tzinfo=None)
      delta = vu - now
  return delta


def certificate_expiration(t):
  deltas = []
  certs = t.iterfind('.//{%s}X509Certificate' % NS['ds'])
  for cert in certs:
    cert = ''.join(cert.text.split())
    pem = ""
    s = 0
    while s < len(cert):
      pem += "\n%s" % cert[s:s + 64]
      s += 64
    pem = '-----BEGIN CERTIFICATE-----' + pem + '\n-----END CERTIFICATE-----'
    cert = x509.load_pem_x509_certificate(pem.encode('utf8'), default_backend())
    now = datetime.utcnow()
    vu = cert.not_valid_after
    delta = vu - now
    deltas.append(delta)
    if delta < timedelta(days=7):
      print(cert.not_valid_after)
  return min(deltas)
