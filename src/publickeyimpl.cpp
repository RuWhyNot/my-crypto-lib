#include "publickeyimpl.h"

#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

namespace Crypto
{
	static KeyVersion THIS_KEY_VERSION = 20;

	PublicKeyImpl::PublicKeyImpl(const CryptoPP::RSAFunction& initData)
	{
		publicKey = CryptoPP::RSA::PublicKey(initData);
	}

	PublicKey::Ptr PublicKeyImpl::CreateFromData(Data::Ptr keyData)
	{
		PublicKeyImpl *rawPublicKeyPtr = new PublicKeyImpl();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		// first two bytes is version (skip them)
		int nSize = (int)rawKeyData[2] << 8 | rawKeyData[3];

		int dataShift = 4;
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

		uint8_t *rawCipherDataPtr = new uint8_t[encryptor.FixedCiphertextLength() + 2];
		rawCipherDataPtr[0] = THIS_KEY_VERSION >> 8;
		rawCipherDataPtr[1] = THIS_KEY_VERSION & 0xFF;

		encryptor.Encrypt(rng, rawData.data(), rawData.size(), rawCipherDataPtr + 2);
		Data::RawData rawCipherData(rawCipherDataPtr, rawCipherDataPtr + encryptor.FixedCiphertextLength() + 2);

		delete[] rawCipherDataPtr;

		return Data::Create(rawCipherData);
	}

	bool PublicKeyImpl::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

		const Data::RawData& messageData = data->GetRawDataRef();
		const Data::RawData& signatureData = signature->ToData()->GetRawDataRef();

		return verifier.VerifyMessage(messageData.data(), messageData.size(), signatureData.data() + 2, signatureData.size() - 2);
	}

	Data::Ptr PublicKeyImpl::ToData() const
	{
		Data::RawData rawData;

		CryptoPP::Integer exponent = publicKey.GetPublicExponent();
		CryptoPP::Integer modulus = publicKey.GetModulus();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		int dataShift = 4;

		rawData.resize(dataShift + expSize + modSize);
		rawData[0] = THIS_KEY_VERSION >> 8; // first two bytes contain key version
		rawData[1] = THIS_KEY_VERSION & 0xFF;
		rawData[2] = expSize >> 8; // next two bytes contain exponent size
		rawData[3] = expSize & 0xFF;

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
