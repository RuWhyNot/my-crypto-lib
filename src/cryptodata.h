#ifndef CRYPTODATA_H
#define CRYPTODATA_H

#include <memory>
#include <vector>

namespace Crypto
{
	class Data
	{
	public:
		typedef std::shared_ptr<Data> Ptr;

	public:
		Data();
		explicit Data(const std::string& data);
		explicit Data(const std::vector<uint8_t>& data);

		~Data();

		std::string ToString() const;
		std::string ToHex() const;

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
#endif // CRYPTODATA_H
