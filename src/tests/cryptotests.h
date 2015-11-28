#pragma once

#include "../keyfactory.h"
#include "../keyring.h"

namespace CryptoTests
{
	extern Crypto::KeyFactory TestKeyFactory;

	bool CryptNEncryptTestSmallText(bool silent = false);
	bool CryptNEncryptTestBigText(bool silent = false);
	bool SignNVerifyTest(bool silent = false);

	bool RunAlltests(bool silent = false);
	bool RunAlltestsNTimes(int n);
}
