require 'securerandom'
require 'base64'

describe "PolarSSl cipher" do
  let(:iv)  { Base64.encode64(SecureRandom.random_bytes(16)) }
  let(:key) { 'MY24BYTEKEY2345678901234' }
  let(:cipher_text) { "Keep it secret, keep it shaved" }
  let(:enc_context) { PolarSSL::Cipher::CipherContext.new }
  #let(:dec_context) { PolarSSL::Cipher::CipherContext.new }
  let(:cipher_type) do
    PolarSSL::Cipher::CipherInfo.new(PolarSSL.cipher_info_from_string('AES-192-CTR'))
  end

  let(:enc_output) { FFI::MemoryPointer.new(128) }
  let(:dec_output) { FFI::MemoryPointer.new(128) }

  let(:enc_output_length_pointer) { FFI::MemoryPointer.new(128) }
  let(:dec_output_length_pointer) { FFI::MemoryPointer.new(128) }

  before do
    # Setup encryption
    PolarSSL.cipher_init_ctx enc_context, cipher_type
    PolarSSL.cipher_reset iv
    PolarSSL.cipher_setkey enc_context, key, key.size * 8, PolarSSL::Cipher::OPERATION_ENCRYPT
    PolarSSL.cipher_update enc_context, cipher_text, cipher_text.size, enc_output, enc_output_length_pointer
    PolarSSL.cipher_finish enc_context, enc_output, enc_output_length_pointer

    # Setup decryption
    PolarSSL.cipher_init_ctx enc_context, cipher_type
    PolarSSL.cipher_reset iv
    PolarSSL.cipher_setkey enc_context, key, key.size * 8, PolarSSL::Cipher::OPERATION_ENCRYPT
    encrypted_data = enc_output.read_string
    PolarSSL.cipher_update enc_context, encrypted_data, 30, dec_output, dec_output_length_pointer
    PolarSSL.cipher_finish enc_context, dec_output, dec_output_length_pointer
  end

  it 'can encrypt/decrypt data' do
    expect(dec_output.read_string).to eq cipher_text
  end
end
