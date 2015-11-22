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
		typedef std::vector<uint8_t> RawData;

	public:
		static Ptr Create(const std::string& data);
		static Ptr Create(const std::vector<uint8_t>& data);

		virtual ~Data();

		std::string ToString() const;
		std::string ToHex() const;
		std::string ToBase64() const;

		const RawData& GetRawDataRef() const;

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
