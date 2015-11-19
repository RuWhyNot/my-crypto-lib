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
		explicit Data(const std::string& data);
		explicit Data(const std::vector<uint8_t>& data);
		explicit Data(const FileStream::Ptr data);

		virtual ~Data();

		std::string ToString() const;
		std::string ToHex() const;

	private:
		void Init();

		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
#endif // CRYPTODATA_H
