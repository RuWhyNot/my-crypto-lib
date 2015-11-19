#ifndef FILESTREAM_H
#define FILESTREAM_H

#include <memory>

namespace Crypto
{
	class FileStream
	{
	public:
		typedef std::shared_ptr<FileStream> Ptr;

	public:
		explicit FileStream(const std::string& fileName);
		~FileStream();
	};
}

#endif // FILESTREAM_H
