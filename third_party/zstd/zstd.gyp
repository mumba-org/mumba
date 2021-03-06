{
  'targets': [
    {
      'target_name': 'zstd',
      'type': 'static_library',
      'sources': [
        'lib/zstd.h',
        'lib/common/pool.h',
        'lib/common/threading.h',
        'lib/common/bitstream.h',
        'lib/common/error_private.h',
        'lib/common/zstd_errors.h',
        'lib/common/fse.h',
        'lib/common/huf.h',
        'lib/common/mem.h',
        'lib/common/zstd_internal.h',
        'lib/compress/zstd_compress.h',
        'lib/compress/zstd_fast.h',
        'lib/compress/zstd_double_fast.h',
        'lib/compress/zstd_lazy.h',
        'lib/compress/zstd_opt.h',
        'lib/compress/zstd_ldm.h',
        'lib/compress/zstdmt_compress.h',
        'lib/dictBuilder/zdict.h',
        'lib/deprecated/zbuff.h',
        'lib/common/entropy_common.c',
        'lib/common/fse_decompress.c',
        'lib/common/threading.c',
        'lib/common/pool.c',
        'lib/common/zstd_common.c',
        'lib/common/error_private.c',
        'lib/common/xxhash.c',
        'lib/compress/fse_compress.c',
        'lib/compress/huf_compress.c',
        'lib/compress/zstd_compress.c',
        'lib/compress/zstdmt_compress.c',
        'lib/compress/zstd_fast.c',
        'lib/compress/zstd_double_fast.c',
        'lib/compress/zstd_lazy.c',
        'lib/compress/zstd_opt.c',
        'lib/compress/zstd_ldm.c',
        'lib/decompress/huf_decompress.c',
        'lib/decompress/zstd_decompress.c',
        'lib/dictBuilder/cover.c',
        'lib/dictBuilder/divsufsort.c',
        'lib/dictBuilder/zdict.c',
        'lib/deprecated/zbuff_common.c',
        'lib/deprecated/zbuff_compress.c',
        'lib/deprecated/zbuff_decompress.c'
      ],
      'dependencies' : [
        #'zlib_x86_simd'
      ],
      'include_dirs': [
        'lib',
        'lib/common',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'lib',
          'lib/common',
        ],
      },
      'conditions': [
        ['OS!="ios" and (target_arch=="ia32" or target_arch=="x64")', {
          #'sources' : [ 'x86.c', ],
        }],
      ],
    },
  ],
}
