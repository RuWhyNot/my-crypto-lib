#pragma once

#include <memory>
#include <vector>

namespace Crypto
{
	class Data
	{
	public:
		typedef std::shared_ptr<Data> Ptr;
		typedef std::vector<uint8_t> RawData;

		enum Encoding {
			Base64,
			Hex
		};

	public:
		static Ptr Create(const std::wstring& message);
		static Ptr Create(const std::string& data, Encoding encoding);
		static Ptr Create(const std::vector<uint8_t>& data);

		virtual ~Data();

		std::wstring ToString() const;
		std::string ToHex() const;
		std::string ToBase64() const;

		const RawData& GetRawDataRef() const;

	private:
		Data();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
