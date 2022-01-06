/*******************************************************************************
* Copyright 2020 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#include "dnnl_common.hpp"
#include "dnnl_debug.hpp"

#include "prelu/prelu.hpp"

namespace prelu {

std::ostream &operator<<(std::ostream &s, const prb_t &prb) {
    using ::operator<<;

    dump_global_params(s);
    settings_t def;

    if (canonical || prb.dir != def.dir[0]) s << "--dir=" << prb.dir << " ";
    if (canonical || prb.sdt != def.sdt[0]) s << "--sdt=" << prb.sdt << " ";
    if (canonical || prb.stag != def.stag[0]) s << "--stag=" << prb.stag << " ";
    s << prb.attr;
    s << prb.sdims;

    return s;
}

} // namespace prelu
