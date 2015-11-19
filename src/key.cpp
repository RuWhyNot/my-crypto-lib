#include "key.h"

#include "../cryptopp/rsa.h"
#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"
namespace Crypto
{
	class Key::Impl
	{
	public:
		CryptoPP::RSA::PublicKey publicKey;
		CryptoPP::RSA::PrivateKey privateKey;
	};

	Key::Key()
		: pimpl(new Impl())
	{

	}

	Key::~Key()
	{

	}

	void Key::Generate(unsigned int seed)
	{
		CryptoPP::MT19937 rng(seed);
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, 512);

		pimpl->publicKey = CryptoPP::RSA::PublicKey(params);
		pimpl->privateKey = CryptoPP::RSA::PrivateKey(params);
	}

	Data::Ptr Key::EncryptData(const Data::Ptr data)
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

	Data::Ptr Key::DecryptData(const Data::Ptr cryptedData)
	{
		std::string result;

		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor d(pimpl->privateKey);

		CryptoPP::StringSource ss2(cryptedData->ToString(), true,
			new CryptoPP::PK_DecryptorFilter(rng, d,
				new CryptoPP::StringSink(result)
		   ) // PK_DecryptorFilter
		); // StringSource

		return std::make_shared<Data>(result);
	}

	Signature::Ptr Key::SignData(const Data::Ptr cryptedData)
	{
		return Signature::Ptr();
	}

	bool Key::VerifySignature(const Data::Ptr data, Signature::Ptr signature)
	{
		return false;
	}

} // namespace Crypto
