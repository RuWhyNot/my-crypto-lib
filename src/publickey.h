#pragma once

#include <memory>
#include "cryptodata.h"
#include "signature.h"

namespace Crypto
{
	///
	/// Interface for public key
	///
	class PublicKey
	{
	public:
		typedef std::shared_ptr<PublicKey> Ptr;

	public:
		virtual ~PublicKey() = default;

		virtual Data::Ptr EncryptData(const Data::Ptr data) const = 0;
		virtual bool VerifySignature(const Data::Ptr data, Signature::Ptr signature) const = 0;

		virtual Fingerprint GetFingerprint() const = 0;

		virtual Data::Ptr ToData() const = 0;
	};
}
