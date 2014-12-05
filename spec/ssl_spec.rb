require 'pry'

describe "PolarSSl ssl" do

  context '.ssl_set_endpoint' do
    let(:ssl_context) { FFI::MemoryPointer.new(1024, 1) }

    before do
      PolarSSL.ssl_init(ssl_context)
    end

    after do
      PolarSSL.ssl_free ssl_context
    end

    it 'sets the endpoint type' do
      expect PolarSSL.ssl_set_endpoint(ssl_context, PolarSSL::SSL::SSL_IS_CLIENT)
    end
  end

  context '.ssl_set_authmode' do
    let(:ssl_context) { FFI::MemoryPointer.new(1024, 1) }

    before do
      PolarSSL.ssl_init(ssl_context)
    end

    after do
      PolarSSL.ssl_free ssl_context
    end

    it 'sets the authmode' do
      expect PolarSSL.ssl_set_authmode(ssl_context, PolarSSL::SSL::SSL_VERIFY_REQUIRED)
    end
  end

  context '.ssl_set_rng' do
    let(:ssl_context) { FFI::MemoryPointer.new(1024, 1) }
    let(:ctr_drbg_context) { PolarSSL::CtrDrbg::CtrDrbgContext.new }

    before do
      PolarSSL.ssl_init(ssl_context)
      ctr_drbg_context[:p_entropy] = PolarSSL::Entropy::EntropyContext.new
    end

    after do
      PolarSSL.ssl_free ssl_context
    end

    it 'sets the random number generator' do
      expect PolarSSL.ssl_set_rng(ssl_context, ctr_drbg_context, FFI::MemoryPointer.new(:pointer))
    end
  end
end
