{
  'targets': [
    {
      'target_name': 'nodejs_test_store_provider',
      'type': 'shared_library',
      'product_extension': 'so',
      'includes': ['../common.gypi'],
      'conditions': [
        ['node_use_openssl=="true"', {
          'sources': ['nodejs_test_store_provider.cc'],
          'include_dirs': ['../../../deps/openssl/openssl/include'],
        }, {
          'type': 'none',
        }],
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_LDFLAGS+': [
              '-undefined',
              'dynamic_lookup',
            ],
          },
        }],
      ],
    },
  ],
}
