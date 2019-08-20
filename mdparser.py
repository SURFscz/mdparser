#!/usr/bin/env python

import sys
import utils
from datetime import timedelta

def parse_saml_metadata(source):
  validation = dict()
  validation['error'] = None
  validation['md_expires'] = None
  validation['crt_expires'] = None

  try:
    t = utils.parse_xml(source)
    t = utils.root(t)

    # XSD validation
    utils.validate_document(t)

    # Expiration check
    validation['md_expires'] = utils.metadata_expiration(t)

    # Certificate expiration
    # Everybody seems to use expired TSC's
    #validation['crt_expires'] = utils.certificate_expiration(t)

  except Exception as ex:
    validation['error'] = ex

  return validation


if len(sys.argv) < 2:
    sys.exit(sys.argv[0] + "  <argument>")

md = open(sys.argv[1], "rb")
v = parse_saml_metadata(md)


error = v['error']
md_expires = v['md_expires']
crt_expires = v['crt_expires']

if (error):
  print("Error: %s" % error)

if (md_expires and md_expires < timedelta(days = 1)):
  print("MD expires: %ss" % md_expires)
  sys.exit(1)

if (crt_expires and crt_expires < timedelta(days = 7)):
  print("CRT expires: %ss" % crt_expires)

exit(0)
md.close()
