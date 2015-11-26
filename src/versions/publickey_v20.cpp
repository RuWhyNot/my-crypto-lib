#include "publickey_v20.h"

#include "../../cryptopp/algparam.h"
#include "../../cryptopp/external/mersenne.h"
#include "../../cryptopp/base64.h"
#include "../../cryptopp/aes.h"
#include "../../cryptopp/sha.h"

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

		// first two bytes is version (skip them)
		int nSize = (int)rawKeyData[2] << 8 | rawKeyData[3];

		int dataShift = 4;
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
		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		int serviceDataSize = 4;
		uint8_t *rawCipherDataPtr = new uint8_t[encryptor.FixedCiphertextLength() + serviceDataSize];
		rawCipherDataPtr[0] = THIS_KEY_VERSION >> 8;
		rawCipherDataPtr[1] = THIS_KEY_VERSION & 0xFF;
		rawCipherDataPtr[2] = fingerprint >> 8;
		rawCipherDataPtr[3] = fingerprint & 0xFF;

		encryptor.Encrypt(rng, rawData.data(), rawData.size(), rawCipherDataPtr + serviceDataSize);
		Data::RawData rawCipherData(rawCipherDataPtr, rawCipherDataPtr + encryptor.FixedCiphertextLength() + serviceDataSize);

		delete[] rawCipherDataPtr;

		return Data::Create(rawCipherData);
	}

	bool PublicKey_v20::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

		const Data::RawData& messageData = data->GetRawDataRef();
		const Data::RawData& signatureData = signature->ToData()->GetRawDataRef();

		int serviceDataSize = 4;
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
} // namespace Crypto
