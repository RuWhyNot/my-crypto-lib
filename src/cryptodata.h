#ifndef CRYPTODATA_H
#define CRYPTODATA_H

#include <memory>
#include <vector>
#include "filestream.h"

namespace Crypto
{
	class Data
	{
	public:
		typedef std::shared_ptr<Data> Ptr;

	public:
		static Ptr Create(const std::string& data);
		static Ptr Create(const std::vector<uint8_t>& data);
		static Ptr Create(const FileStream::Ptr data);

		virtual ~Data();

		std::string ToString() const;
		std::string ToHex() const;
		std::string ToBase64() const;

		const std::vector<const uint8_t>& GetRawDataRef() const;

		void SaveToFile(const std::string& fileName) const;
		void LoadFromFile(const std::string& fileName);

	protected:
		Data();

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
#endif // CRYPTODATA_H
