#include "keyring.h"

namespace Crypto
{
	typedef std::pair<Fingerprint, PublicKey::Ptr> PublicPair;
	typedef std::pair<Fingerprint, PrivateKey::Ptr> PrivatePair;

	Keyring::Ptr Keyring::Create()
	{
		return Ptr(new Keyring());
	}

	void Keyring::AddPublicKey(PublicKey::Ptr key)
	{
		publicKeys.insert(PublicPair(key->GetFingerprint(), key));
	}

	void Keyring::AddPrivateKey(PrivateKey::Ptr key)
	{
		privateKeys.insert(PrivatePair(key->GetFingerprint(), key));
	}

	Data::Ptr Keyring::DecryptData(const Data::Ptr cryptedData) const
	{
		auto itPair = privateKeys.equal_range(cryptedData->GetFingerprint());

		for (auto it = itPair.first; it != itPair.second; it++)
		{
			Data::Ptr plain = it->second->DecryptData(cryptedData);
			if (!plain->IsEmpty())
			{
				return plain;
			}
		}

		return Data::CreateEmpty();
	}

	bool Keyring::VerifySignature(const Data::Ptr data, Signature::Ptr signature) const
	{
		auto itPair = publicKeys.equal_range(signature->ToData()->GetFingerprint());

		for (auto it = itPair.first; it != itPair.second; it++)
		{
			if (it->second->VerifySignature(data, signature))
			{
				return true;
			}
		}

		return false;
	}

} // namespace Crypto
