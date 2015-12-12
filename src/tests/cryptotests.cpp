#include "cryptotests.h"

#include <time.h>
#include <iostream>

#include "../versions/v20/publickey_v20.h"
#include "../versions/v20/privatekey_v20.h"

namespace CryptoTests
{
	Crypto::KeyFactory TestKeyFactory;

	bool CryptNEncryptTestSmallText(bool silent)
	{
		using namespace Crypto;

		Crypto::Keyring::Ptr keyring = Crypto::Keyring::Create();

		Crypto::Data::Ptr publicKeyData;

		{
			PrivateKey::Ptr privateKey = TestKeyFactory.GeneratePrivateKey(KeyServiceVersions::LATEST_KNOWN_VERSION, time(NULL), 1024);
			keyring->AddPrivateKey(privateKey);

			PublicKey::Ptr publicKey = privateKey->GetPublicKey();
			publicKeyData = publicKey->ToData();
		}

		PublicKey::Ptr publicKey = TestKeyFactory.PublicKeyFromData(publicKeyData);

		std::string plainText = "Text to encrypt";

		Crypto::Data::Ptr plain(Crypto::Data::Create(plainText));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);
		if (!silent) { std::cout << "Cipher: " << cipher->ToBase64() << std::endl; }

		Crypto::Data::Ptr recovered = keyring->DecryptData(cipher);
		if (!silent) { std::cout << "Recovered text: " << recovered->ToString() << std::endl; }

		return recovered->ToString() == plainText;
	}

	bool CryptNEncryptTestBigText(bool silent)
	{
		using namespace Crypto;

		PrivateKey::Ptr privateKey = TestKeyFactory.GeneratePrivateKey(KeyServiceVersions::LATEST_KNOWN_VERSION, time(NULL), 1024);
		PublicKey::Ptr publicKey = privateKey->GetPublicKey();

		std::string plainText = "Lorem ipsum dolor sit amet, vero nemore in vis. Epicuri suscipit mea in, his ex idque urbanitas. "
								"Ea nec causae inciderint, facilis voluptaria te usu, meis prodesset omittantur nec ei. An sale de"
								"nique eos, saepe tantas maiestatis ne pri. Justo praesent comprehensam cu mel, ius an reque verea"
								"r, ea dolor civibus eum.";

		Crypto::Data::Ptr plain(Crypto::Data::Create(plainText));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);
		if (!silent) { std::cout << "Cipher: " << cipher->ToBase64() << std::endl; }

		Crypto::Data::Ptr recovered = privateKey->DecryptData(cipher);
		if (!silent) { std::cout << "Recovered text: " << recovered->ToString() << std::endl; }

		return recovered->ToString() == plainText;
	}

	bool SignNVerifyTest(bool silent)
	{
		using namespace Crypto;

		Crypto::Keyring::Ptr keyring = Crypto::Keyring::Create();

		Crypto::Data::Ptr privateKeyData;
		{
			PrivateKey::Ptr privateKey = TestKeyFactory.GeneratePrivateKey(KeyServiceVersions::LATEST_KNOWN_VERSION, time(NULL), 1024);
			privateKeyData = privateKey->ToData();

			PublicKey::Ptr publicKey = privateKey->GetPublicKey();
			keyring->AddPublicKey(publicKey);
		}

		PrivateKey::Ptr privateKey = TestKeyFactory.PrivateKeyFromData(privateKeyData);

		Crypto::Data::Ptr plain(Crypto::Data::Create("Text to sign"));

		Signature::Ptr signature = privateKey->SignData(plain);
		if (!silent) { std::cout << "Signature: " << signature->ToData()->ToBase64() << std::endl; }

		{
			bool isCorrect = keyring->VerifySignature(plain, signature);
			if (!silent) { std::cout << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
			if (!isCorrect) { return false; }
		}

		{
			Crypto::Data::Ptr invalidData = Crypto::Data::Create(plain->ToString() + "asd");
			bool isCorrect = keyring->VerifySignature(invalidData, signature);
			if (!silent) { std::cout << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
			if (isCorrect) { return false; }
		}

		return true;
	}

	bool FromToStrDataTest(bool silent)
	{
		static const std::string TEST_STR("Text for base64 test");
		Crypto::Data::Ptr data = Crypto::Data::Create(TEST_STR);

		{
			std::string result = Crypto::Data::Create(data->ToBase64(), Crypto::Data::Encoding::Base64)->ToString();
			if (!silent) { std::cout << "Base64 recovered text: " << result << std::endl; }
			if (result != TEST_STR) { return false; }
		}

		{
			std::string result = Crypto::Data::Create(data->ToHex(), Crypto::Data::Encoding::Hex)->ToString();
			if (!silent) { std::cout << "Hex recovered text: " << result << std::endl; }
			if (result != TEST_STR) { return false; }
		}

		return true;
	}

	bool ErrorKeysCastTest(bool silent)
	{
		{
			Crypto::PublicKey::Ptr publicKey = Crypto::PublicKey_v20::CreateFromData(Crypto::Data::Create("test"));
			if (publicKey) { return false; }
		}

		{
			Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey_v20::CreateFromData(Crypto::Data::Create("test"));
			if (privateKey) { return false; }
		}

		{
			Crypto::PublicKey::Ptr publicKey = TestKeyFactory.PublicKeyFromData(Crypto::Data::Create("test"));
			if (publicKey) { return false; }
		}

		{
			Crypto::PrivateKey::Ptr privateKey = TestKeyFactory.PrivateKeyFromData(Crypto::Data::Create("test"));
			if (privateKey) { return false; }
		}

		return true;
	}


	bool RunAlltests(bool silent)
	{
		if (!CryptNEncryptTestSmallText(silent)) { return false; }
		if (!CryptNEncryptTestBigText(silent)) { return false; }
		if (!SignNVerifyTest(silent)) { return false; }
		if (!FromToStrDataTest(silent)) { return false; }
		if (!ErrorKeysCastTest(silent)) { return false; }
		return true;
	}

	bool RunAlltestsNTimes(int n)
	{
		for (int i = 0; i < n; ++i) {
			if (!RunAlltests(true)) {
				return false;
			}
		}
		return true;
	}
} // namespace CryptoTests
