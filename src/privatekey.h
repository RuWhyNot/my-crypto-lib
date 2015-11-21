#ifndef PRIVATEKEY_H
#define PRIVATEKEY_H

#include "publickey.h"

namespace Crypto
{
	class PrivateKey
	{
	public:
		typedef std::shared_ptr<PrivateKey> Ptr;

	public:
		~PrivateKey();

		static PrivateKey::Ptr Generate(unsigned int seed);
		static PrivateKey::Ptr CreateFromData(Data::Ptr keyData);

		Data::Ptr DecryptData(const Data::Ptr cryptedData);
		Signature::Ptr SignData(const Data::Ptr data);

		PublicKey::Ptr GetPublicKey();

		Data::Ptr ToData() const;

	private:
		PrivateKey();

		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}

#endif // PRIVATEKEY_H
