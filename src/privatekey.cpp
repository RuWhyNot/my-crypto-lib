#include "privatekey.h"

#include "../cryptopp/rsa.h"
#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

#include "publickeyimpl.h"

namespace Crypto
{
	class PrivateKey::Impl
	{
	public:
		CryptoPP::RSA::PrivateKey privateKey;
	};

	PrivateKey::PrivateKey()
		: pimpl(new Impl())
	{

	}

	PrivateKey::~PrivateKey()
	{

	}

	PrivateKey::Ptr PrivateKey::Generate(unsigned int seed)
	{
		PrivateKey::Ptr result(new PrivateKey());

		CryptoPP::MT19937 rng(seed);
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, 512);

		result->pimpl->privateKey = CryptoPP::RSA::PrivateKey(params);

		return result;
	}

	PrivateKey::Ptr PrivateKey::CreateFromData(Data::Ptr keyData)
	{
		PrivateKey *rawPrivateKeyPtr = new PrivateKey();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		int nSize = rawKeyData[0];
		int eSize = rawKeyData[1];

		int dataShift = 2;
		CryptoPP::Integer exponent(rawKeyData.data() + dataShift, nSize);

		dataShift += nSize;
		CryptoPP::Integer modulus(rawKeyData.data() + dataShift, eSize);

		dataShift += eSize;
		CryptoPP::Integer modInverse(rawKeyData.data() + dataShift, rawKeyData.size() - dataShift);

		rawPrivateKeyPtr->pimpl->privateKey.Initialize(modulus, exponent, modInverse);

		// raw ptr will be deleted automatically
		return PrivateKey::Ptr(rawPrivateKeyPtr);
	}

	Data::Ptr PrivateKey::DecryptData(const Data::Ptr cryptedData)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(pimpl->privateKey);

		const Data::RawData& rawCryptedData = cryptedData->GetRawDataRef();

		uint8_t *rawResultDataPtr = new uint8_t[decryptor.MaxPlaintextLength(rawCryptedData.size())];

		CryptoPP::DecodingResult decodingResult = decryptor.Decrypt(rng, rawCryptedData.data(), rawCryptedData.size(), rawResultDataPtr);
		Data::RawData rawResultData(rawResultDataPtr, rawResultDataPtr + decodingResult.messageLength);

		delete[] rawResultDataPtr;

		if (decodingResult.isValidCoding) {
			return Data::Create(rawResultData);
		} else {
			return Data::Create("");
		}
	}

	Signature::Ptr PrivateKey::SignData(const Data::Ptr data)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(pimpl->privateKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		uint8_t *rawSignatureDataPtr = new uint8_t[signer.MaxSignatureLength()];

		size_t length =  signer.SignMessage(rng, rawData.data(), rawData.size(), rawSignatureDataPtr);
		Data::RawData rawSignatureData(rawSignatureDataPtr, rawSignatureDataPtr + length);

		delete[] rawSignatureDataPtr;

		return Signature::CreateFromData(Data::Create(rawSignatureData));
	}

	PublicKey::Ptr PrivateKey::GetPublicKey()
	{
		return std::make_shared<PublicKeyImpl>(pimpl->privateKey);
	}

	Data::Ptr PrivateKey::ToData() const
	{
		Data::RawData rawData;
		CryptoPP::MT19937 rng;

		CryptoPP::Integer exponent = pimpl->privateKey.GetPublicExponent();
		CryptoPP::Integer modulus = pimpl->privateKey.GetModulus();
		CryptoPP::Integer modInverse = pimpl->privateKey.GetPrivateExponent();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		const int mmiSize = modInverse.ByteCount();
		int dataShift = 2;

		rawData.resize(dataShift + expSize + modSize + mmiSize);
		rawData[0] = exponent.ByteCount(); // first byte is exponent size
		rawData[1] = modulus.ByteCount(); // second byte is modulus size

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
