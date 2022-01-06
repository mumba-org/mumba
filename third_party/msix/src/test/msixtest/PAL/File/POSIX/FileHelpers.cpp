//
//  Copyright (C) 2019 Microsoft.  All rights reserved.
//  See LICENSE file in the project root for full license information.
// 
#include "msixtest_int.hpp"
#include "FileHelpers.hpp"
#include "catch.hpp"

#include <memory>
#include <algorithm>
#include <string>
#include <map>
#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fts.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

namespace MsixTest {

    namespace Directory {

        template <class Lambda>
        bool WalkDirectory(const std::string& path, Lambda& visitor)
        {
            static std::string dot(".");
            static std::string dotdot("..");

            std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
            if (dir.get() == nullptr) { return false; }
            struct dirent* entry;
            while ((entry = readdir(dir.get())) != nullptr) 
            {
                std::string name = std::string(entry->d_name);
                if (dot != name && dotdot != name)
                {
                    std::string newPath = path + "/" + name;
                    if (entry->d_type == DT_DIR)
                    {
                        WalkDirectory(newPath, visitor);
                    }
                    if (!visitor(newPath, entry))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        // best effort to clean the directory
        bool CleanDirectory(const std::string& directory)
        {
            auto lambda = [](const std::string& file, dirent*)
            {
                return (std::remove(file.c_str()) == 0);
            };

            if(!WalkDirectory(directory, lambda))
            {
                return false;
            }

            return (std::remove(directory.c_str()) == 0);
        }

        bool CompareDirectory(const std::string& directory, const std::map<std::string, std::uint64_t>& files)
        {
            auto filesCopy(files);

            auto lambda = [&filesCopy, &directory](const std::string& path, dirent* entry)
            {
                if (entry->d_type == DT_DIR) { return true; }

                // Remove root directory
                auto file = path;
                file.erase(0, directory.size() + 1);

                auto find = filesCopy.find(file);
                if (find == filesCopy.end())
                {
                    std::cout << "File: " << file << " doesn't exists in expected files." << std::endl;
                    return false;
                }

                // Get size
                struct stat sb;
                if (stat(path.c_str(), &sb) == -1)
                {
                    std::cout << "File: " << file << " stat call failed with " << std::to_string(errno) << std::endl;
                    return false;
                }
                std::uint64_t size = static_cast<std::uint64_t>(sb.st_size);
                if (find->second != size)
                {
                    std::cout << "File: " << file << " wrong size. Expected: " << find->second << " Got: " << size << std::endl;
                    return false;
                }
                filesCopy.erase(find);
                return true;
            };

            if(!WalkDirectory(directory, lambda))
            {
                return false;
            }

            // If the map is empty, then all the files are located
            return filesCopy.empty();
        }

        // Converts path to posix separator
        std::string PathAsCurrentPlatform(const std::string& path)
        {
            std::string result(path);
            std::replace(result.begin(), result.end(), '\\', '/');
            return result;
        }

        // Ensures that the path is an absolute one
        std::string PathAsAbsolute(const std::string& path)
        {
            if (path.empty())
            {
                return path;
            }

            std::string cwdStr;

            if (path[0] == '/')
            {
                cwdStr = path;
            }
            else
            {
                char cwdArr[PATH_MAX];
                REQUIRE_NOT_NULL(getcwd(cwdArr, PATH_MAX));

                cwdStr = cwdArr;
                cwdStr += '/';
                cwdStr += path;
            }

            char result[PATH_MAX];
            result[0] = '\0';
            char* returnVal = realpath(cwdStr.c_str(), result);
            
            if (returnVal == nullptr && result[0] != '\0' && errno == ENOENT)
            {
                // Some systems will treat a missing file as an error,
                // but still give you the answer.  If they do that, use the path.
            }
            else
            {
                REQUIRE_NOT_NULL(returnVal);
            }
            
            return std::string{ result };
        }
    }
}
