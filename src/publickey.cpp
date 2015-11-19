#include "publickey.h"

#include "../cryptopp/rsa.h"
#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

namespace Crypto
{
	class PublicKey::Impl
	{
	public:
		CryptoPP::RSA::PublicKey publicKey;
	};

	PublicKey::PublicKey(const CryptoPP::RSAFunction& initData)
		: pimpl(new Impl())
	{
		pimpl->publicKey = CryptoPP::RSA::PublicKey(initData);
	}

	PublicKey::PublicKey()
		: pimpl(new Impl())
	{

	}

	PublicKey::~PublicKey()
	{

	}

	Data::Ptr PublicKey::EncryptData(const Data::Ptr data)
	{
		std::string result;

		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pimpl->publicKey);

		CryptoPP::StringSource ss1(data->ToString(), true,
			new CryptoPP::PK_EncryptorFilter(rng, encryptor,
				new CryptoPP::StringSink(result)
		   ) // PK_EncryptorFilter
		); // StringSource

		return std::make_shared<Data>(result);
	}

	bool PublicKey::VerifySignature(const Data::Ptr data, Signature::Ptr signature)
	{
		return false;
	}

	std::string PublicKey::ToString() const
	{
		return "";
	}

	std::string PublicKey::ToHex() const
	{
		return "";
	}
}
