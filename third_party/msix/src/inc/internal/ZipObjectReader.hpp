//
//  Copyright (C) 2019 Microsoft.  All rights reserved.
//  See LICENSE file in the project root for full license information.
// 
#pragma once

#include "third_party/msix/src/inc/shared/Exceptions.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/ZipObject.hpp"

#include <vector>
#include <map>
#include <memory>

namespace MSIX {
    // This represents a raw stream over a.zip file.
    class MSIX_API ZipObjectReader final : public ComClass<ZipObjectReader, IStorageObject>, ZipObject
    {
    public:
        ZipObjectReader(const ComPtr<IStream>& stream);

        // IStorageObject methods
        std::vector<std::string> GetFileNames(FileNameOptions options) override;
        ComPtr<IStream> GetFile(const std::string& fileName) override;
        std::string GetFileName() override;

    protected:
        std::map<std::string, ComPtr<IStream>> m_streams;
    };
}
