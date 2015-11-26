#pragma once

#include <functional>
#include <map>
#include <vector>

#include "keyversions.h"
#include "privatekey.h"
#include "publickey.h"

namespace Crypto
{
	class KeyFactory
	{
	public:
		typedef std::shared_ptr<KeyFactory> Ptr;

		typedef std::function<PrivateKey::Ptr(Data::Ptr)> PrivateKeyConvertFn;
		typedef std::function<PublicKey::Ptr(Data::Ptr)> PublicKeyConvertFn;

		typedef std::function<PrivateKey::Ptr(unsigned long, int)> KeyGenerateFn;

	public:
		static Ptr Create();

		void RegisterDataKeysConverters(KeyVersion version, PrivateKeyConvertFn privateKeyConverter, PublicKeyConvertFn publicKeyConverter);
		void RegisterDataKeyGenerator(KeyVersion version, KeyGenerateFn privateKeyGenerator);

		PrivateKey::Ptr PrivateKeyFromData(Data::Ptr data);
		PublicKey::Ptr PublicKeyFromData(Data::Ptr data);

		PrivateKey::Ptr GeneratePrivateKey(KeyVersion version, unsigned long seed, int size = 512);
		std::vector<KeyVersion> GetAvailableVersions();
		KeyVersion GetLatestVersion();

	private:
		struct KeyConverters
		{
			PrivateKeyConvertFn privateKeyConverter;
			PublicKeyConvertFn publicKeyConverter;

			KeyConverters(PrivateKeyConvertFn prKC, PublicKeyConvertFn pubKC)
				: privateKeyConverter(prKC)
				, publicKeyConverter(pubKC)
			{}
		};

		typedef std::map<KeyVersion, KeyConverters> ConvertersMap;
		typedef std::map<KeyVersion, KeyGenerateFn> GeneratorsMap;

	private:
		KeyVersion latestVersion;
		ConvertersMap converters;
		GeneratorsMap generators;
	};
} // namespace Crypto
