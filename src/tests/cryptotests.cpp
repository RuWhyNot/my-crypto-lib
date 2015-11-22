#include "cryptotests.h"

#include <time.h>

#include "../privatekey.h"

namespace CryptoTests
{
	bool CryptNEncryptTest()
	{
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL));
		Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();

		std::string plainText = "Text to encrypt";

		Crypto::Data::Ptr plain(Crypto::Data::Create(plainText));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);

		Crypto::Data::Ptr recovered = privateKey->DecryptData(cipher);

		return recovered->ToString() == plainText;
	}

	bool SignNVerifyTest()
	{
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL));
		Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();

		Crypto::Data::Ptr plain(Crypto::Data::Create("Text to sign"));

		Crypto::Signature::Ptr signature = privateKey->SignData(plain);

		{
			bool isCorrect = publicKey->VerifySignature(plain, signature);
			if (!isCorrect) { return false; }
		}

		{
			Crypto::Data::Ptr invalidData = Crypto::Data::Create(plain->ToString() + "asd");
			bool isCorrect = publicKey->VerifySignature(invalidData, signature);
			if (isCorrect) { return false; }
		}

		return true;
	}

	bool RunAlltests()
	{
		if (!CryptNEncryptTest()) { return false; }
		if (!SignNVerifyTest()) { return false; }
		return true;
	}

	bool RunAlltestsNTimes(int n)
	{
		for (int i = 0; i < n; ++i) {
			if (!RunAlltests()) {
				return false;
			}
		}
		return true;
	}

} // namespace CryptoTests
