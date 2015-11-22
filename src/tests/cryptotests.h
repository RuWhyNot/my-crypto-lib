#pragma once

namespace CryptoTests
{
	bool CryptNEncryptTest(bool silent = false);
	bool SignNVerifyTest(bool silent = false);

	bool RunAlltests(bool silent = false);
	bool RunAlltestsNTimes(int n);
}
