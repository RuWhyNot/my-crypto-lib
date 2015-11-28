#pragma once

#include "../../../cryptopp/rsa.h"

#include "../../publickey.h"
#include "../../fingerprint.h"

namespace Crypto
{
	class PublicKey_v20 : public PublicKey
	{
	public:
		PublicKey_v20(const CryptoPP::RSAFunction& initData);

		static PublicKey::Ptr CreateFromData(Data::Ptr keyData);

		virtual Data::Ptr EncryptData(const Data::Ptr data) const override;
		virtual bool VerifySignature(const Data::Ptr data, Signature::Ptr signature) const override;

		virtual Fingerprint GetFingerprint() const override;

		virtual Data::Ptr ToData() const override;

	private:
		PublicKey_v20();

		static Fingerprint CalcFingerprint(Data::Ptr publicKeyData);

	private:
		CryptoPP::RSA::PublicKey publicKey;
		Fingerprint fingerprint;
	};
}
