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

	}

	Data::Ptr PrivateKey::DecryptData(const Data::Ptr cryptedData)
	{
		std::string result;

		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor d(pimpl->privateKey);

		CryptoPP::StringSource ss2(cryptedData->ToString(), true,
			new CryptoPP::PK_DecryptorFilter(rng, d,
				new CryptoPP::StringSink(result)
		   ) // PK_DecryptorFilter
		); // StringSource

		return Data::Create(result);
	}

	Signature::Ptr PrivateKey::SignData(const Data::Ptr cryptedData)
	{
		return Signature::Ptr();
	}

	PublicKey::Ptr PrivateKey::GetPublicKey()
	{
		return std::make_shared<PublicKeyImpl>(pimpl->privateKey);
	}

	Data::Ptr PrivateKey::ToData() const
	{

	}
}
