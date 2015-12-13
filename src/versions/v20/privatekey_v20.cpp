#include "privatekey_v20.h"

#include <time.h>

#include "../../../cryptopp/algparam.h"
#include "../../../cryptopp/external/mersenne.h"
#include "../../../cryptopp/base64.h"
#include "../../../cryptopp/aes.h"
#include "../../../cryptopp/modes.h"

#include "publickey_v20.h"

namespace Crypto
{
	static KeyVersion THIS_KEY_VERSION = 20;

	PrivateKey_v20::PrivateKey_v20()
	{
	}

	PrivateKey::Ptr PrivateKey_v20::Generate(unsigned long seed, int size)
	{
		PrivateKey_v20* resultRawPtr = new PrivateKey_v20();

		if (seed == 0) {
			seed = time(NULL);
		}

		CryptoPP::MT19937 rng(seed);
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, size);

		resultRawPtr->privateKey = CryptoPP::RSA::PrivateKey(params);

		resultRawPtr->fingerprint = resultRawPtr->GetPublicKey()->GetFingerprint();

		// raw ptr will be deleted automatically
		return PrivateKey::Ptr(resultRawPtr);
	}

	PrivateKey::Ptr PrivateKey_v20::CreateFromData(Data::Ptr keyData)
	{
		PrivateKey_v20 *rawPrivateKeyPtr = new PrivateKey_v20();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		int dataShift = 7;
		if (rawKeyData.size() < (size_t)dataShift) {
			return PrivateKey::Ptr(nullptr);
		}

		if (rawKeyData[0] != Data::GetByteFromType(Data::Type::PrivateKey)) {
			return PrivateKey::Ptr(nullptr);
		}

		KeyVersion version = (int)rawKeyData[1] << 8 | rawKeyData[2];
		if (version != THIS_KEY_VERSION) {
			return PrivateKey::Ptr(nullptr);
		}

		int nSize = (int)rawKeyData[3] << 8 | rawKeyData[4];
		if (nSize <= 0 || nSize >= (int)rawKeyData.size() - dataShift) {
			return PrivateKey::Ptr(nullptr);
		}

		int eSize = (int)rawKeyData[5] << 8 | rawKeyData[6];
		if (eSize <= 0 || eSize >= (int)rawKeyData.size() - (dataShift + nSize)) {
			return PrivateKey::Ptr(nullptr);
		}

		CryptoPP::Integer exponent(rawKeyData.data() + dataShift, nSize);

		dataShift += nSize;
		CryptoPP::Integer modulus(rawKeyData.data() + dataShift, eSize);

		dataShift += eSize;
		CryptoPP::Integer modInverse(rawKeyData.data() + dataShift, rawKeyData.size() - dataShift);

		rawPrivateKeyPtr->privateKey.Initialize(modulus, exponent, modInverse);

		rawPrivateKeyPtr->fingerprint = rawPrivateKeyPtr->GetPublicKey()->GetFingerprint();

		// raw ptr will be deleted automatically
		return PrivateKey::Ptr(rawPrivateKeyPtr);
	}

	Data::Ptr PrivateKey_v20::DecryptData(const Data::Ptr cryptedData) const
	{
		CryptoPP::MT19937 rng(time(NULL));
		CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);

		const Data::RawData& rawCryptedData = cryptedData->GetRawDataRef();

		const int serviceDataSize = 5;

		if (rawCryptedData.size() < (size_t)serviceDataSize) {
			return Data::CreateEmpty();
		}

		if (rawCryptedData[0] != Data::GetByteFromType(Data::Type::Cipher)) {
			return Data::CreateEmpty();
		}

		uint8_t *resultRawDataPtr = new uint8_t[rsaDecryptor.FixedMaxPlaintextLength()];

		int rsaPartSize = rsaDecryptor.FixedCiphertextLength();
		CryptoPP::DecodingResult decodingResult = rsaDecryptor.Decrypt(rng, rawCryptedData.data() + serviceDataSize, rsaPartSize, resultRawDataPtr);
		int messageLength = decodingResult.messageLength;

		if (static_cast<int>(rawCryptedData.size()) > serviceDataSize + rsaPartSize)
		{ // we have aes encrypted part
			int dataShift = 2;
			int aesKeySize = resultRawDataPtr[0] << 8 | resultRawDataPtr[1];
			int ivSize = messageLength - aesKeySize - dataShift;
			uint8_t aesKey[aesKeySize];
			uint8_t iv[ivSize];

			memcpy(aesKey, resultRawDataPtr + dataShift, aesKeySize);
			memcpy(iv, resultRawDataPtr + dataShift + aesKeySize, ivSize);

			messageLength = rawCryptedData.size() - serviceDataSize - rsaPartSize;

			delete[] resultRawDataPtr;
			resultRawDataPtr = new uint8_t[messageLength];

			CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption aesDecryptor(aesKey, sizeof(aesKey), iv, 1);
			aesDecryptor.ProcessData(resultRawDataPtr, rawCryptedData.data() + serviceDataSize + rsaPartSize, messageLength);
		}

		Data::RawData rawResultData(resultRawDataPtr, resultRawDataPtr + messageLength);

		delete[] resultRawDataPtr;

		if (decodingResult.isValidCoding) {
			return Data::Restore(rawResultData);
		} else {
			return Data::CreateEmpty();
		}
	}

	Signature::Ptr PrivateKey_v20::SignData(const Data::Ptr data) const
	{
		CryptoPP::MT19937 rng(time(NULL));
		CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		int serviceDataSize = 5;
		uint8_t *rawSignatureDataPtr = new uint8_t[signer.MaxSignatureLength() + serviceDataSize];
		rawSignatureDataPtr[0] = Data::GetByteFromType(Data::Type::Signature);
		rawSignatureDataPtr[1] = THIS_KEY_VERSION >> 8;
		rawSignatureDataPtr[2] = THIS_KEY_VERSION & 0xFF;
		rawSignatureDataPtr[3] = fingerprint >> 8;
		rawSignatureDataPtr[4] = fingerprint & 0xFF;

		size_t length = signer.SignMessage(rng, rawData.data(), rawData.size(), rawSignatureDataPtr + serviceDataSize);
		Data::RawData rawSignatureData(rawSignatureDataPtr, rawSignatureDataPtr + length + serviceDataSize);

		delete[] rawSignatureDataPtr;

		return Signature::CreateFromData(Data::Restore(rawSignatureData));
	}

	PublicKey::Ptr PrivateKey_v20::GetPublicKey()
	{
		return std::make_shared<PublicKey_v20>(privateKey);
	}

	Fingerprint PrivateKey_v20::GetFingerprint() const
	{
		return fingerprint;
	}

	Data::Ptr PrivateKey_v20::ToData() const
	{
		Data::RawData rawData;

		CryptoPP::Integer exponent = privateKey.GetPublicExponent();
		CryptoPP::Integer modulus = privateKey.GetModulus();
		CryptoPP::Integer modInverse = privateKey.GetPrivateExponent();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		const int mmiSize = modInverse.ByteCount();
		int dataShift = 7;

		rawData.resize(dataShift + expSize + modSize + mmiSize);
		rawData[0] = Data::GetByteFromType(Data::Type::PrivateKey);
		rawData[1] = THIS_KEY_VERSION >> 8; // two bytes contain key version
		rawData[2] = THIS_KEY_VERSION & 0xFF;
		rawData[3] = expSize >> 8; // two bytes contain exponent size
		rawData[4] = expSize & 0xFF;
		rawData[5] = modSize >> 8; // two bytes contain modulus size
		rawData[6] = modSize & 0xFF;

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

		return Data::Restore(rawData);
	}
} // namespace Crypto
