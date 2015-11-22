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
		//return PublicKey::Ptr(new PublicKeyImpl());
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
		return Data::Create("");
	}
} // namespace Crypto
