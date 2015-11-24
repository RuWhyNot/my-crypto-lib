#pragma once

#include "publickey.h"

namespace Crypto
{
	class PrivateKey
	{
	public:
		typedef std::shared_ptr<PrivateKey> Ptr;

	public:
		~PrivateKey();

		static PrivateKey::Ptr Generate(unsigned int seed, int size = 512);
		static PrivateKey::Ptr CreateFromData(Data::Ptr keyData);

		Data::Ptr DecryptData(const Data::Ptr cryptedData);
		Signature::Ptr SignData(const Data::Ptr data);

		PublicKey::Ptr GetPublicKey();

		Data::Ptr ToData() const;

	private:
		PrivateKey();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
