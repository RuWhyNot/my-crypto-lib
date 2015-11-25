#pragma once

#include "../cryptopp/rsa.h"

#include "publickey.h"

namespace Crypto
{
	class PublicKeyImpl : public PublicKey
	{
	public:
		PublicKeyImpl(const CryptoPP::RSAFunction& initData);

		static PublicKey::Ptr CreateFromData(Data::Ptr keyData);

		virtual Data::Ptr EncryptData(const Data::Ptr data) const override;
		virtual bool VerifySignature(const Data::Ptr data, Signature::Ptr signature) const override;

		virtual Data::Ptr ToData() const override;

	private:
		PublicKeyImpl();

	private:
		CryptoPP::RSA::PublicKey publicKey;
	};
}
