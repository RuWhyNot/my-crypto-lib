#include "keyfactory.h"

namespace Crypto
{

	KeyFactory::Ptr KeyFactory::Create()
	{
		return Ptr(new KeyFactory());
	}

	void KeyFactory::RegisterDataKeysConverters(KeyVersion version, KeyFactory::PrivateKeyConvertFn privateKeyConverter, KeyFactory::PublicKeyConvertFn publicKeyConverter)
	{
		converters.insert(std::pair<KeyVersion, KeyConverters>(version, KeyConverters(privateKeyConverter, publicKeyConverter)));
	}

	void KeyFactory::RegisterDataKeyGenerator(KeyVersion version, KeyFactory::KeyGenerateFn privateKeyGenerator)
	{
		generators.insert(std::pair<KeyVersion, KeyGenerateFn>(version, privateKeyGenerator));
	}

	PrivateKey::Ptr KeyFactory::PrivateKeyFromData(Data::Ptr data)
	{
		KeyVersion version = data->GetVersion();

		if (version == KeyServiceVersions::ERROR_VERSION) {
			return PrivateKey::Ptr(nullptr);
		}

		auto it = converters.find(version);

		if (it != converters.end()) {
			if (it->second.privateKeyConverter) {
				return it->second.privateKeyConverter(data);
			}
		}

		return PrivateKey::Ptr(nullptr);
	}

	PublicKey::Ptr KeyFactory::PublicKeyFromData(Data::Ptr data)
	{
		KeyVersion version = data->GetVersion();

		if (version == KeyServiceVersions::ERROR_VERSION) {
			return PublicKey::Ptr(nullptr);
		}

		auto it = converters.find(version);

		if (it != converters.end()) {
			if (it->second.publicKeyConverter) {
				return it->second.publicKeyConverter(data);
			}
		}

		return PublicKey::Ptr(nullptr);
	}

	PrivateKey::Ptr KeyFactory::GeneratePrivateKey(KeyVersion version, unsigned long seed, int size)
	{
		auto it = generators.find(version);

		if (it != generators.end()) {
			if (it->second) {
				return it->second(seed, size);
			}
		}

		return PrivateKey::Ptr(nullptr);
	}

	std::vector<KeyVersion> KeyFactory::GetAvailableVersions()
	{
		std::vector<KeyVersion> versions;
		versions.reserve(generators.size());

		for (const auto& pair : generators) {
			versions.push_back(pair.first);
		}

		return versions;
	}

	KeyVersion KeyFactory::GetLatestVersion()
	{
		if (!generators.empty()) {
			return generators.rbegin()->first;
		} else {
			return KeyServiceVersions::ERROR_VERSION;
		}
	}

} // namespace Crypto
