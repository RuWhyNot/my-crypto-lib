#pragma once

#include "publickey.h"
#include "fingerprint.h"

namespace Crypto
{
	class PrivateKey
	{
	public:
		typedef std::shared_ptr<PrivateKey> Ptr;

	public:
		virtual ~PrivateKey() = default;

		virtual Data::Ptr DecryptData(const Data::Ptr cryptedData) const = 0;
		virtual Signature::Ptr SignData(const Data::Ptr data) const = 0;

		virtual PublicKey::Ptr GetPublicKey() = 0;

		virtual Fingerprint GetFingerprint() const = 0;

		virtual Data::Ptr ToData() const = 0;
	};
}
