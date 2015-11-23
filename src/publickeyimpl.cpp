#include "publickeyimpl.h"

#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

namespace Crypto
{
	PublicKeyImpl::PublicKeyImpl(const CryptoPP::RSAFunction& initData)
	{
		publicKey = CryptoPP::RSA::PublicKey(initData);
	}

	PublicKeyImpl::~PublicKeyImpl()
	{

	}

	PublicKey::Ptr PublicKeyImpl::CreateFromData(Data::Ptr keyData)
	{
		PublicKeyImpl *rawPublicKeyPtr = new PublicKeyImpl();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		int nSize = rawKeyData[0];

		int dataShift = 1;
		CryptoPP::Integer exponent(rawKeyData.data() + dataShift, nSize);

		dataShift += nSize;
		CryptoPP::Integer modulus(rawKeyData.data() + dataShift, rawKeyData.size() - dataShift);

		rawPublicKeyPtr->publicKey.Initialize(modulus, exponent);

		// raw ptr will be deleted automatically
		return PublicKey::Ptr(rawPublicKeyPtr);
	}

	Data::Ptr PublicKeyImpl::EncryptData(const Data::Ptr data) const
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		uint8_t *rawCipherDataPtr = new uint8_t[encryptor.FixedCiphertextLength()];

		encryptor.Encrypt(rng, rawData.data(), rawData.size(), rawCipherDataPtr);
		Data::RawData rawCipherData(rawCipherDataPtr, rawCipherDataPtr + encryptor.FixedCiphertextLength());

		delete[] rawCipherDataPtr;

		return Data::Create(rawCipherData);
	}

	bool PublicKeyImpl::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

		const Data::RawData& messageData = data->GetRawDataRef();
		const Data::RawData& signatureData = signature->ToData()->GetRawDataRef();

		return verifier.VerifyMessage(messageData.data(), messageData.size(), signatureData.data(), signatureData.size());
	}

	Data::Ptr PublicKeyImpl::ToData() const
	{
		Data::RawData rawData;

		CryptoPP::Integer exponent = publicKey.GetPublicExponent();
		CryptoPP::Integer modulus = publicKey.GetModulus();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		int dataShift = 1;

		rawData.resize(dataShift + expSize + modSize);
		rawData[0] = exponent.ByteCount(); // first byte is exponent size

		for (int i = 0; i < expSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = exponent.GetByte(expSize - i - 1);
		}

		dataShift += expSize;
		for (int i = 0; i < modSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = modulus.GetByte(modSize - i - 1);
		}

		return Data::Create(rawData);
	}

	PublicKeyImpl::PublicKeyImpl()
	{

	}
} // namespace Crypto
