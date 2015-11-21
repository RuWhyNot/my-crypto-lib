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

	}

	Data::Ptr PublicKeyImpl::EncryptData(const Data::Ptr data) const
	{
		std::string result;

		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

		CryptoPP::StringSource ss1(data->ToString(), true,
			new CryptoPP::PK_EncryptorFilter(rng, encryptor,
				new CryptoPP::StringSink(result)
		   ) // PK_EncryptorFilter
		); // StringSource

		return Data::Create(result);
	}

	bool PublicKeyImpl::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		return false;
	}

	Data::Ptr PublicKeyImpl::ToData() const
	{
		return Data::Create("");
	}
}
