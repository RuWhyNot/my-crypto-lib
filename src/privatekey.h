#pragma once

#include "publickey.h"

namespace Crypto
{
	class PrivateKey
	{
	public:
		typedef std::shared_ptr<PrivateKey> Ptr;

	public:
		virtual ~PrivateKey() = default;

		virtual Data::Ptr DecryptData(const Data::Ptr cryptedData) = 0;
		virtual Signature::Ptr SignData(const Data::Ptr data) = 0;

		virtual PublicKey::Ptr GetPublicKey() = 0;

		virtual Data::Ptr ToData() const = 0;
	};
}
