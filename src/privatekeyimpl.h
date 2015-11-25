#pragma once

#include "privatekey.h"

namespace Crypto
{
	class PrivateKeyImpl : public PrivateKey
	{
	public:
		static PrivateKey::Ptr Generate(unsigned long seed, int size = 512);
		static PrivateKey::Ptr CreateFromData(Data::Ptr keyData);

		Data::Ptr DecryptData(const Data::Ptr cryptedData);
		Signature::Ptr SignData(const Data::Ptr data);

		PublicKey::Ptr GetPublicKey();

		Data::Ptr ToData() const;

	private:
		PrivateKeyImpl();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
