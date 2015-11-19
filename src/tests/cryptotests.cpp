#include "cryptotests.h"

#include <iostream>
#include <time.h>

#include "../key.h"

namespace CryptoTests
{
	void CryptEncryptTest()
	{
		Crypto::Key key;
		key.Generate(time(NULL));

		Crypto::Data::Ptr plain(std::make_shared<Crypto::Data>("RSA Encryption"));

		Crypto::Data::Ptr cipher = key.EncryptData(plain);

		std::cout << "Crypted text: \"" << cipher->ToString() << "\"" << std::endl;

		Crypto::Data::Ptr recovered = key.DecryptData(cipher);

		std::cout << "Recovered plain text: \"" << recovered->ToString() << "\"" << std::endl;
	}

} // namespace CryptoTests
