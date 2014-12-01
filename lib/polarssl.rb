require 'ffi'

module PolarSSL
  POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED = -0x0034
  
  extend FFI::Library
  ffi_lib ENV['POLARSSL_PATH'] || '/usr/local/lib/libpolarssl.so'

  Operation = enum :operation, [
    :none,   -1, 
    :encrypt, 0, 
    :decrypt, 1
  ]

  CipherType = enum :cipher_type, [
    :none, 0,
    :null,
    :aes_128_ecb,
    :aes_192_ecb,
    :aes_256_ecb,
    :aes_128_cbc,
    :aes_192_cbc,
    :aes_256_cbc,
    :aes_128_cfb128,
    :aes_192_cfb128,
    :aes_256_cfb128,
    :aes_128_ctr,
    :aes_192_ctr,
    :aes_256_ctr,
    :aes_128_gcm,
    :aes_192_gcm,
    :aes_256_gcm,
    :camellia_128_ecb,
    :camellia_192_ecb,
    :camellia_256_ecb,
    :camellia_128_cbc,
    :camellia_192_cbc,
    :camellia_256_cbc,
    :camellia_128_cfb128,
    :camellia_192_cfb128,
    :camellia_256_cfb128,
    :camellia_128_ctr,
    :camellia_192_ctr,
    :camellia_256_ctr,
    :camellia_128_gcm,
    :camellia_192_gcm,
    :camellia_256_gcm,
    :des_ecb,
    :des_cbc,
    :des_ede_ecb,
    :des_ede_cbc,
    :des_ede3_ecb,
    :des_ede3_cbc,
    :blowfish_ecb,
    :blowfish_cbc,
    :blowfish_cfb64,
    :blowfish_ctr,
    :arc4_128,
    :aes_128_ccm,
    :aes_192_ccm,
    :aes_256_ccm,
    :camellia_128_ccm,
    :camellia_192_ccm,
    :camellia_256_ccm
  ]

  CipherMode = enum :cipher_mode, [
    :none, 0,
    :ecb,
    :cbc,
    :cfb,
    :ofb,
    :ctr,
    :gcm,
    :stream,
    :ccm
  ]

  class SSL
    class MallocFailed < StandardError; end
    class NetWantRead  < StandardError; end
    class NetWantWrite < StandardError; end
    class Error        < StandardError; end

    SSL_IS_CLIENT = 0
    SSL_IS_SERVER = 1

    SSL_VERIFY_NONE     = 0
    SSL_VERIFY_OPTIONAL = 1
    SSL_VERIFY_REQUIRED = 2
  end

  class Cipher

    OPERATION_NONE    = -1
    OPERATION_ENCRYPT = 0
    OPERATION_DECRYPT = 1

    class UnsupportedCipher < StandardError; end
    class BadInputData      < StandardError; end
    class Error             < StandardError; end

    class CipherInfo < ::FFI::Struct
      layout :type, CipherType,
             :mode, CipherMode,
             :key_length, :uint,
             :name,       :string,
             :iv_size,    :uint,
             :flags,      :int,
             :block_size,  :uint,
             :base,       :pointer # CipherBase
    end

    class CipherContext < ::FFI::Struct
      layout :cipher_info,      :pointer,
             :key_length,       :int,
             :operation,        Operation,
             :add_padding,      :pointer,
             :get_padding,      :pointer,
             :unprocessed_data, :uchar,
             :unprocessed_len,  :size_t,
             :iv,               :uchar,
             :iv_size,          :size_t,
             :cipher_ctx,       :pointer

    end
  end

  class CtrDrbg
    class AesContext < ::FFI::Struct 
      layout :nr,  :int,
             :rk,  :uint32,
             :buf, :uint32 
    end

    class CtrDrbgContext < ::FFI::Struct
      layout :counter,               :uint16,
             :reseed_counter,        :int,
             :prediction_resistance, :int,
             :entropy_len,           :size_t,
             :reseed_interval,       :int,
             :aes_context,           AesContext,
             :f_entropy,             :int,
             :p_entropy,             :pointer
    end

  end

  class Entropy
    class SourceState < ::FFI::Struct
      layout :f_source, :pointer,
        :p_source,      :pointer,
        :size,          :size_t,
        :threshold,     :size_t
    end

    class Sha512Context < ::FFI::Struct
      layout :total, :uint64,
        :state,      :uint64,
        :buffer,     :uchar,
        :ipad,       :uchar,
        :opad,       :uchar,
        :is384,      :int
    end

    class EntropyContext < ::FFI::Struct
      layout :accumulator,  Sha512Context,
           :source_count,  :int,
           :source_state, SourceState
    end
  end

  #attach_function :entropy_init,  [ Entropy::EntropyContext ], :void
  #attach_function :entropy_free,  [ Entropy::EntropyContext ], :void
  #attach_function :ctr_drbg_init, [ CtrDrbg::CtrDrbgContext ], :void
  #attach_function :ctr_drbg_free, [ CtrDrbg::CtrDrbgContext ], :void
  attach_function :ctr_drbg_self_test, [ :int ],  :int

  # Returns a pointer which must be passed to Cipher::CipherInfo
  attach_function :cipher_info_from_string,
    [ :string ], # e.g. 'AES-192-CTR'
    Cipher::CipherInfo

  # Params: pointers to CipherContext and CipherInfo
  attach_function :cipher_init_ctx,
    [ :pointer,
      :pointer ],
    :int # zero for success, error otherwise

  attach_function :cipher_reset,
    [ :string ], # e.g. base64 encoded bytes as a string Base64.encode64(SecureRandom.random_bytes(16))
    :int

  attach_function :cipher_setkey,
    [ :pointer,    # instance of CipherContext
      :string,     # string key
      :int,        # key length in bits
      Operation ], # enum. See Operation definition
    :int

  attach_function :cipher_update,
    [ :pointer,   # instance of CipherContext
      :string,    # string cipher text
      :size_t,    # length of cipher text
      :pointer,   # pointer where encrypted bytes are written
      :pointer ], # pointer where length of encrypted bytes is updated
    :int

  attach_function :cipher_finish,
    [ :pointer,   # instance of CipherContext
      :pointer,   # pointer where encrypted bytes are written
      :pointer ], # pointer where length of encrypted bytes is updated
   :int
end

