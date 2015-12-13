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

		enum class Type
		{
			Error
			,Empty
			,PlainText
			,PlainData
			,PublicKey
			,PrivateKey
			,Cipher
			,Signature
		};

	public:
		static Ptr CreateEmpty();
        static Ptr Create(const std::string& message);
        static Ptr Create(const std::string& data, Encoding encoding);
		static Ptr Create(const std::vector<uint8_t>& data);

		static Ptr Restore(const std::string& data, Encoding encoding);
		static Ptr Restore(const std::vector<uint8_t>& data);


		virtual ~Data();

		std::string ToPlainString() const;
		std::string ToPlainHex() const;
		std::string ToPlainBase64() const;
		RawData ToPlainData() const;

		std::string GetHexData() const;
		std::string GetBase64Data() const;
		const RawData& GetRawDataRef() const;

		bool IsEmpty() const;

		Type GetType() const;

		// applicable only for keys data, crypted data and signature data
		KeyVersion GetVersion();
		// applicable only for crypted data and signature data
		Fingerprint GetFingerprint() const;

		static uint8_t GetByteFromType(Type type);

	private:
		Data();

		std::string GetHex(int dataShift) const;
		std::string GetBase64(int dataShift) const;
		static Ptr FromData(const std::string &data, Data::Encoding encoding, int dataShift);

		static Type GetTypeFromByte(uint8_t typeByte);

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}
