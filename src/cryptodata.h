#pragma once

#include <memory>
#include <vector>

#include "keyversions.h"

namespace Crypto
{
	class Data
	{
	public:
		typedef std::shared_ptr<Data> Ptr;
		typedef std::vector<uint8_t> RawData;

	public:
		static Ptr Create(const std::string& data);
		static Ptr Create(const std::vector<uint8_t>& data);

		virtual ~Data();

		std::string ToString() const;
		std::string ToHex() const;
		std::string ToBase64() const;

		const RawData& GetRawDataRef() const;

		// applicable only for keys data, crypted data and signature data
		KeyVersion GetVersion();
	private:
		Data();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
