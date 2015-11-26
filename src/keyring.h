#pragma once

#include <map>

#include "fingerprint.h"
#include "publickey.h"
#include "privatekey.h"

namespace Crypto
{
	class Keyring
	{
	public:
		typedef std::shared_ptr<Keyring> Ptr;

	public:
		static Ptr Create();

		void AddPublicKey(PublicKey::Ptr key);
		void AddPrivateKey(PrivateKey::Ptr key);

		Data::Ptr DecryptData(const Data::Ptr cryptedData) const;
		bool VerifySignature(const Data::Ptr data, Signature::Ptr signature) const;

	private:
		std::multimap<Fingerprint, PublicKey::Ptr> publicKeys;
		std::multimap<Fingerprint, PrivateKey::Ptr> privateKeys;
	};
} // namespace Crypto
