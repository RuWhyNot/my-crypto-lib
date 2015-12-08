#pragma once

#include <memory>
#include <vector>

#include "keyversions.h"
#include "fingerprint.h"

namespace Crypto
{
	class Data
	{
	public:
		typedef std::shared_ptr<Data> Ptr;
		typedef std::vector<uint8_t> RawData;

        enum class Encoding
        {
            Hex
            ,Base64
        };

	public:
		static Ptr CreateEmpty();
        static Ptr Create(const std::string& message);
        static Ptr Create(const std::string& data, Encoding encoding);
		static Ptr Create(const std::vector<uint8_t>& data);

		virtual ~Data();

		std::string ToString() const;
		std::string ToHex() const;
		std::string ToBase64() const;

		bool IsEmpty() const;

		const RawData& GetRawDataRef() const;

		// applicable only for keys data, crypted data and signature data
		KeyVersion GetVersion();
		// applicable only for crypted data and signature data
		Fingerprint GetFingerprint() const;

	private:
		Data();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
