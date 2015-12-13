#include "publickey_v20.h"

#include "../../../cryptopp/algparam.h"
#include "../../../cryptopp/external/mersenne.h"
#include "../../../cryptopp/base64.h"
#include "../../../cryptopp/aes.h"
#include "../../../cryptopp/sha.h"
#include "../../../cryptopp/modes.h"

#include <time.h>

namespace Crypto
{
	static KeyVersion THIS_KEY_VERSION = 20;

	PublicKey_v20::PublicKey_v20()
	{
	}

	PublicKey_v20::PublicKey_v20(const CryptoPP::RSAFunction& initData)
	{
		PublicKey_v20();
		publicKey = CryptoPP::RSA::PublicKey(initData);
		fingerprint = CalcFingerprint(ToData());
	}

	Fingerprint PublicKey_v20::CalcFingerprint(Data::Ptr publicKeyData)
	{
		CryptoPP::SHA1 hash;

		std::vector<uint8_t> digest(hash.DigestSize());

		hash.CalculateDigest(digest.data(), publicKeyData->GetRawDataRef().data(), publicKeyData->GetRawDataRef().size());

		digest.resize(2);

		return digest[0] << 8 | digest[1];
	}

	PublicKey::Ptr PublicKey_v20::CreateFromData(Data::Ptr keyData)
	{
		PublicKey_v20 *rawPublicKeyPtr = new PublicKey_v20();

		const Data::RawData& rawKeyData = keyData->GetRawDataRef();

		int dataShift = 5;
		if (rawKeyData.size() < (size_t)dataShift) {
			return PublicKey::Ptr(nullptr);
		}

		if (rawKeyData[0] != Data::GetByteFromType(Data::Type::PublicKey)) {
			return PublicKey::Ptr(nullptr);
		}

		KeyVersion version = (int)rawKeyData[1] << 8 | rawKeyData[2];
		if (version != THIS_KEY_VERSION) {
			return PublicKey::Ptr(nullptr);
		}

		int nSize = (int)rawKeyData[3] << 8 | rawKeyData[4];
		if (nSize <= 0 || nSize >= (int)rawKeyData.size()) {
			return PublicKey::Ptr(nullptr);
		}

		CryptoPP::Integer exponent(rawKeyData.data() + dataShift, nSize);

		dataShift += nSize;
		CryptoPP::Integer modulus(rawKeyData.data() + dataShift, rawKeyData.size() - dataShift);

		rawPublicKeyPtr->publicKey.Initialize(modulus, exponent);

		rawPublicKeyPtr->fingerprint = CalcFingerprint(keyData);

		// raw ptr will be deleted automatically
		return PublicKey::Ptr(rawPublicKeyPtr);
	}

	Data::Ptr PublicKey_v20::EncryptData(const Data::Ptr data) const
	{
		CryptoPP::MT19937 rng(time(NULL));
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		int serviceDataSize = 5;
		uint8_t *rawCipherDataPtr = nullptr;
		uint8_t *dataToRsaCryptPtr = nullptr;
		int dataToRsaCryptSize = 0;
		int encryptedDataLength = 0;

		if (rawData.size() > encryptor.FixedMaxPlaintextLength())
		{ // use AES, then crypt aes key with RSA
			encryptedDataLength = serviceDataSize + encryptor.FixedCiphertextLength() + rawData.size();
			rawCipherDataPtr = new uint8_t[encryptedDataLength];

			CryptoPP::SecByteBlock aesKey(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
			rng.GenerateBlock(aesKey, aesKey.size());

			uint8_t iv[CryptoPP::AES::BLOCKSIZE];
			rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

			CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(aesKey, aesKey.size(), iv, 1);
			cfbEncryption.ProcessData(rawCipherDataPtr + (serviceDataSize + encryptor.FixedCiphertextLength()), rawData.data(), rawData.size());

			int dataShift = 2;
			dataToRsaCryptSize = dataShift + aesKey.SizeInBytes() + CryptoPP::AES::BLOCKSIZE;
			dataToRsaCryptPtr = new uint8_t[dataToRsaCryptSize];

			dataToRsaCryptPtr[0] = (aesKey.SizeInBytes() & 0xFF00) >> 8;
			dataToRsaCryptPtr[1] = aesKey.SizeInBytes() & 0xFF;

			for (int i = 0, i_size = aesKey.SizeInBytes(); i < i_size; ++i) {
				dataToRsaCryptPtr[dataShift + i] = aesKey[i];
			}

			dataShift += aesKey.SizeInBytes();
			for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i) {
				dataToRsaCryptPtr[dataShift + i] = iv[i];
			}
		}
		else
		{ // if we can encrypt the data only with RSA we do it
			encryptedDataLength = serviceDataSize + encryptor.FixedCiphertextLength();
			rawCipherDataPtr = new uint8_t[encryptedDataLength];
			dataToRsaCryptSize = rawData.size();
			dataToRsaCryptPtr = new uint8_t[dataToRsaCryptSize];
			memcpy(dataToRsaCryptPtr, rawData.data(), dataToRsaCryptSize);
		}

		rawCipherDataPtr[0] = Data::GetByteFromType(Data::Type::Cipher);
		rawCipherDataPtr[1] = (THIS_KEY_VERSION & 0xFF00) >> 8;
		rawCipherDataPtr[2] = THIS_KEY_VERSION & 0xFF;
		rawCipherDataPtr[3] = (fingerprint & 0xFF00) >> 8;
		rawCipherDataPtr[4] = fingerprint & 0xFF;

		encryptor.Encrypt(rng, dataToRsaCryptPtr, dataToRsaCryptSize, rawCipherDataPtr + serviceDataSize);
		Data::RawData rawCipherData(rawCipherDataPtr, rawCipherDataPtr + encryptedDataLength);

		delete[] dataToRsaCryptPtr;
		delete[] rawCipherDataPtr;

		return Data::Restore(rawCipherData);
	}

	bool PublicKey_v20::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		int serviceDataSize = 5;
		const Data::RawData& messageData = data->GetRawDataRef();
		const Data::RawData& signatureData = signature->ToData()->GetRawDataRef();

		if (signatureData.size() < (size_t)serviceDataSize) {
			return false;
		}

		if (signatureData[0] != Data::GetByteFromType(Data::Type::Signature)) {
			return false;
		}

		KeyVersion version = (int)signatureData[1] << 8 | signatureData[2];
		if (version != THIS_KEY_VERSION) {
			return false;
		}

		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
		return verifier.VerifyMessage(messageData.data(), messageData.size(), signatureData.data() + serviceDataSize, signatureData.size() - serviceDataSize);
	}

	Fingerprint PublicKey_v20::GetFingerprint() const
	{
		return fingerprint;
	}

	Data::Ptr PublicKey_v20::ToData() const
	{
		Data::RawData rawData;

		CryptoPP::Integer exponent = publicKey.GetPublicExponent();
		CryptoPP::Integer modulus = publicKey.GetModulus();

		const int expSize = exponent.ByteCount();
		const int modSize = modulus.ByteCount();
		int dataShift = 5;

		rawData.resize(dataShift + expSize + modSize);
		rawData[0] = Data::GetByteFromType(Data::Type::PublicKey);
		rawData[1] = (THIS_KEY_VERSION & 0xFF00) >> 8; // two bytes contain key version
		rawData[2] = THIS_KEY_VERSION & 0xFF;
		rawData[3] = expSize >> 8; // two bytes contain exponent size
		rawData[4] = expSize & 0xFF;

		for (int i = 0; i < expSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = exponent.GetByte(expSize - i - 1);
		}

		dataShift += expSize;
		for (int i = 0; i < modSize; ++i) {
			// inverse bytes order
			rawData[dataShift + i] = modulus.GetByte(modSize - i - 1);
		}

		return Data::Restore(rawData);
	}
} // namespace Crypto
