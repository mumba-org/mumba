/*******************************************************************************
* Copyright 2020-2021 Intel Corporation
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

#include <sstream>

#include "parser.hpp"

#include "reduction/reduction.hpp"

namespace reduction {

void check_correctness(const settings_t &s) {
    for_(const auto &i_sdt : s.sdt)
    for_(const auto &i_ddt : s.ddt)
    for_(const auto &i_stag : s.stag)
    for_(const auto &i_dtag : s.dtag)
    for_(const auto &i_post_ops : s.post_ops)
    for_(const auto &i_alg : s.alg)
    for_(const auto &i_p : s.p)
    for_(const auto &i_eps : s.eps)
    {
        bool ok = s.dims.size() == 2 && s.dims[0].size() == s.dims[1].size();
        if (!ok) SAFE_V(FAIL);

        attr_t attr;
        attr.insert(i_post_ops);
        const prb_t prb(
                s.dims, i_sdt, i_ddt, i_stag, i_dtag, i_alg, i_p, i_eps, attr);
        std::stringstream ss;
        ss << prb;
        const std::string cpp_pstr = ss.str();
        const char *pstr = cpp_pstr.c_str();
        BENCHDNN_PRINT(1, "run: %s\n", pstr);

        res_t res {};
        int status = doit(&prb, &res);

        bool want_perf_report = false;
        parse_result(res, want_perf_report, status, pstr);

        if (want_perf_report && is_bench_mode(PERF)) {
            perf_report_t pr(s.perf_template);
            pr.report(&prb, &res, pstr);
        }

        benchdnn_stat.tests++;
    }
}

int bench(int argc, char **argv) {
    driver_name = "reduction";
    using namespace parser;
    static settings_t s;
    static const settings_t def {};
    for (; argc > 0; --argc, ++argv) {
        const bool parsed_options = parse_bench_settings(argv[0])
                || parse_batch(bench, argv[0])
                || parse_dt(s.sdt, def.sdt, argv[0], "sdt")
                || parse_dt(s.ddt, def.ddt, argv[0], "ddt")
                || parse_tag(s.stag, def.stag, argv[0], "stag")
                || parse_tag(s.dtag, def.dtag, argv[0], "dtag")
                || parse_attr_post_ops(s.post_ops, argv[0])
                || parse_alg(s.alg, def.alg, str2alg, argv[0])
                || parse_vector_option(s.p, def.p, atof, argv[0], "p")
                || parse_vector_option(s.eps, def.eps, atof, argv[0], "eps")
                || parse_perf_template(s.perf_template, s.perf_template_def,
                        s.perf_template_csv, argv[0])
                || parse_reset(s, argv[0]);
        if (!parsed_options) {
            catch_unknown_options(argv[0]);

            parse_multi_dims(s.dims, argv[0]);

            check_correctness(s);
        }
    }

    return parse_last_argument();
}

} // namespace reduction
