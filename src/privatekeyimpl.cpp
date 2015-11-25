#include "privatekeyimpl.h"

#include "../cryptopp/rsa.h"
#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

#include "publickeyimpl.h"
#include "privatekeyimpl.h"

namespace Crypto
{
	static KeyVersion THIS_KEY_VERSION = 20;

	class PrivateKeyImpl::Impl
	{
	public:
		CryptoPP::RSA::PrivateKey privateKey;
	};

	PrivateKeyImpl::PrivateKeyImpl()
		: pimpl(new Impl())
	{

	}

	PrivateKey::Ptr PrivateKeyImpl::Generate(unsigned long seed, int size)
	{
		PrivateKeyImpl* resultRawPtr = new PrivateKeyImpl();

		CryptoPP::MT19937 rng(seed);
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, size);

		resultRawPtr->pimpl->privateKey = CryptoPP::RSA::PrivateKey(params);

		// raw ptr will be deleted automatically
		return PrivateKey::Ptr(resultRawPtr);
	}

	PrivateKey::Ptr PrivateKeyImpl::CreateFromData(Data::Ptr keyData)
	{
		PrivateKeyImpl *rawPrivateKeyPtr = new PrivateKeyImpl();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		// first two bytes is version (skip them)
		int nSize = (int)rawKeyData[2] << 8 | rawKeyData[3];
		int eSize = (int)rawKeyData[4] << 8 | rawKeyData[5];

		int dataShift = 6;
		CryptoPP::Integer exponent(rawKeyData.data() + dataShift, nSize);

		dataShift += nSize;
		CryptoPP::Integer modulus(rawKeyData.data() + dataShift, eSize);

		dataShift += eSize;
		CryptoPP::Integer modInverse(rawKeyData.data() + dataShift, rawKeyData.size() - dataShift);

		rawPrivateKeyPtr->pimpl->privateKey.Initialize(modulus, exponent, modInverse);

		// raw ptr will be deleted automatically
		return PrivateKey::Ptr(rawPrivateKeyPtr);
	}

	Data::Ptr PrivateKeyImpl::DecryptData(const Data::Ptr cryptedData)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(pimpl->privateKey);

		const Data::RawData& rawCryptedData = cryptedData->GetRawDataRef();

		uint8_t *rawResultDataPtr = new uint8_t[decryptor.MaxPlaintextLength(rawCryptedData.size() - 2)];

		CryptoPP::DecodingResult decodingResult = decryptor.Decrypt(rng, rawCryptedData.data() + 2, rawCryptedData.size() - 2, rawResultDataPtr);
		Data::RawData rawResultData(rawResultDataPtr, rawResultDataPtr + decodingResult.messageLength);

		delete[] rawResultDataPtr;

		if (decodingResult.isValidCoding) {
			return Data::Create(rawResultData);
		} else {
			return Data::Create("");
		}
	}

	Signature::Ptr PrivateKeyImpl::SignData(const Data::Ptr data)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(pimpl->privateKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		uint8_t *rawSignatureDataPtr = new uint8_t[signer.MaxSignatureLength() + 2];
		rawSignatureDataPtr[0] = THIS_KEY_VERSION >> 8;
		rawSignatureDataPtr[1] = THIS_KEY_VERSION & 0xFF;

		size_t length = signer.SignMessage(rng, rawData.data(), rawData.size(), rawSignatureDataPtr + 2);
		Data::RawData rawSignatureData(rawSignatureDataPtr, rawSignatureDataPtr + length + 2);

		delete[] rawSignatureDataPtr;

		return Signature::CreateFromData(Data::Create(rawSignatureData));
	}

	PublicKey::Ptr PrivateKeyImpl::GetPublicKey()
	{
		return std::make_shared<PublicKeyImpl>(pimpl->privateKey);
	}

	Data::Ptr PrivateKeyImpl::ToData() const
	{
		Data::RawData rawData;

		CryptoPP::Integer exponent = pimpl->privateKey.GetPublicExponent();
		CryptoPP::Integer modulus = pimpl->privateKey.GetModulus();
		CryptoPP::Integer modInverse = pimpl->privateKey.GetPrivateExponent();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		const int mmiSize = modInverse.ByteCount();
		int dataShift = 6;

		rawData.resize(dataShift + expSize + modSize + mmiSize);
		rawData[0] = THIS_KEY_VERSION >> 8; // first two bytes contain key version
		rawData[1] = THIS_KEY_VERSION & 0xFF;
		rawData[2] = expSize >> 8; // next two bytes contain exponent size
		rawData[3] = expSize & 0xFF;
		rawData[4] = modSize >> 8; // next two bytes contain modulus size
		rawData[5] = modSize & 0xFF;

		for (int i = 0; i < expSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = exponent.GetByte(expSize - i - 1);
		}

		dataShift += expSize;
		for (int i = 0; i < modSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = modulus.GetByte(modSize - i - 1);
		}

		dataShift += modSize;
		for (int i = 0; i < mmiSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = modInverse.GetByte(mmiSize - i - 1);
		}

		return Data::Create(rawData);
	}
} // namespace Crypto
