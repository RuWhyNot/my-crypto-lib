#include "cryptotests.h"

#include <iostream>
#include <time.h>

#include "../privatekey.h"

namespace CryptoTests
{
	void CryptEncryptTest()
	{
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL));
		Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();

		Crypto::Data::Ptr plain(std::make_shared<Crypto::Data>("RSA Encryption"));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);

		std::cout << "Crypted text: \"" << cipher->ToString() << "\"" << std::endl;

		Crypto::Data::Ptr recovered = privateKey->DecryptData(cipher);

		std::cout << "Recovered plain text: \"" << recovered->ToString() << "\"" << std::endl;
	}

} // namespace CryptoTests
