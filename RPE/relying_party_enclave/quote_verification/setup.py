from distutils.core import setup, Extension

verify_dcap_quote_module = Extension('_verify_dcap_quote',
                           sources=['verify_dcap_quote_wrap.cxx', 'verify_dcap_quote.cpp', 'types.cpp',
                                    'hex_string.cpp', 'base64.cpp', 'json/json_utils.cpp', 'json/parson.cpp'],
                           libraries=['sgx_dcap_quoteverify']
                           )

setup(name='verify_dcap_quote',
      version='0.1',
      author="SWIG Docs",
      description="""Simple swig verify_dcap_quote from docs""",
      ext_modules=[verify_dcap_quote_module],
      py_modules=["verify_dcap_quote"],
      )
