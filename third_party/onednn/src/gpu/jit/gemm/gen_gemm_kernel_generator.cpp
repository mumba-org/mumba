/*******************************************************************************
* Copyright 2019-2021 Intel Corporation
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

#include <array>
#include <cstddef>
#include <functional>
#include <stdexcept>
#include <vector>

#include "gpu/jit/gemm/gen_gemm_kernel_generator.hpp"

namespace dnnl {
namespace impl {
namespace gpu {
namespace jit {

using namespace ngen;
using namespace ngen::utils;
using dnnl::impl::utils::one_of;
using ngen::utils::log2;

using std::complex;
using std::vector;

class need_vflag : public std::runtime_error {
public:
    need_vflag() : std::runtime_error("Need virtual flag registers") {}
};

class stub_exception : public std::runtime_error {
public:
    stub_exception()
        : std::runtime_error("Functionality not yet implemented") {}
};

class hw_unsupported_exception : public std::runtime_error {
public:
    hw_unsupported_exception()
        : std::runtime_error("Unsupported in hardware") {}
};

[[noreturn]] static void hw_unsupported() {
    throw hw_unsupported_exception();
}

[[noreturn]] static void stub() {
    throw stub_exception();
}

// Helpers
template <typename U>
static inline Immediate cast(Type T, U val) {
    switch (T) {
        case Type::f16: return half(val);
        case Type::f32: return float(val);
        case Type::u8: return uint8_t(val);
        case Type::s8: return int8_t(val);
        case Type::u16: return uint16_t(val);
        case Type::s16: return int16_t(val);
        case Type::u32: return uint32_t(val);
        case Type::s32: return int32_t(val);
        case Type::u64: return uint64_t(val);
        case Type::s64: return int64_t(val);
        default: stub();
    }
}

static inline Immediate cast(Type T, Scalar<double> val) {
    return cast(T, double(val));
}

template <typename T>
constexpr T clamp(T val, T lo, T hi) {
    return std::min<T>(hi, std::max<T>(lo, val));
}

constexpr bool operator==(const RegData &rd, int i) {
    return false;
}
constexpr bool operator==(const RegData &rd, const Immediate &i) {
    return false;
}
constexpr bool operator!=(const RegData &rd, int i) {
    return true;
}
constexpr bool operator!=(const RegData &rd, const Immediate &i) {
    return true;
}

void noop() {}

static inline int div_up(int value, int divisor) {
    return (value + divisor - 1) / divisor;
}

// Round value down to a multiple of factor.
static inline int align_down(int value, int factor) {
    return factor * (value / factor);
}

// Round value up to a multiple of factor.
static int align_up(int value, int factor) {
    return factor * div_up(value, factor);
}

using dnnl::impl::math::gcd;
using dnnl::impl::math::lcm;

template <typename T>
constexpr bool equal(T t) {
    return true;
}
template <typename T1, typename T2>
constexpr bool equal(T1 t1, T2 t2) {
    return (t1 == t2);
}
template <typename T1, typename T2, typename... To>
constexpr bool equal(T1 t1, T2 t2, To... to) {
    return (t1 == t2) && equal(t2, to...);
}

static inline constexpr bool isGen9IGEMM(HW hw, Type Ta, Type Tb, Type Tc) {
    return (hw < HW::Xe_LP && Ta.size() == 1 && Tb.size() == 1
            && Tc.size() == 4);
}

template <typename T>
static inline constexpr int elementsPerGRF(HW hw) {
    return GRF::bytes(hw) / sizeof(T);
}

static inline constexpr int elementsPerGRF(HW hw, Type T) {
    return GRF::bytes(hw) / T;
}

static inline constexpr int elementsPerGRF(HW hw, DataType dt) {
    return GRF::bytes(hw) / getBytes(dt);
}

static inline bool hasNativeAtomicAdd(
        HW hw, Type T, const MatrixAddressing &atype) {
    if (T.isInteger())
        return true;
    else
        return false;
}

void RegisterBlock::calcBytes(Type T) {
    bytes = align_up(colMajor ? nc : nr, crosspack) * ld * T;
}

int RegisterBlock::nregs() const {
    auto grfBytes = (1 << log2GRFBytes);
    if (offsetBytes & (grfBytes - 1)) stub();
    return (bytes + grfBytes - 1) >> log2GRFBytes;
}

int RegisterBlock::offsetReg() const {
    auto grfBytes = (1 << log2GRFBytes);
    if (offsetBytes & (grfBytes - 1)) stub();
    return offsetBytes >> log2GRFBytes;
}

// Check for "large" crosspack (> 1 DW)
static inline bool isLargeCrosspack(Type T, int crosspack) {
    return (crosspack * T > 4) && (crosspack > 1);
}

void RegisterBlock::simplify(Type T) {
    // If block is completely crosspacked, convert to equivalent layout without crosspack.
    if (crosspack == (colMajor ? nc : nr) && isLargeCrosspack(T, crosspack)) {
        auto od = colMajor ? nr : nc;
        if (ld == od) {
            colMajor = !colMajor;
            ld = crosspack;
            crosspack = 1;
        }
    }
}

static inline constexpr bool isColMajor(MatrixLayout layout) {
    return (layout == MatrixLayout::N || layout == MatrixLayout::Pc);
}

static inline bool isTransposing(AccessType atype) {
    if (atype == AccessType::Scattered) return true;
    if (atype == AccessType::ChannelScattered) return true;
    return false;
}

template <typename T>
Subregister Scalar<T>::getReg(int idx) const {
    if (fixed_value) throw std::runtime_error("Scalar is fixed.");
    return regs[idx & 1];
}

template <typename T>
Subregister Scalar<T>::getRegAvoiding(ngen::HW hw, const RegData &rd) const {
    if (fixed_value) throw std::runtime_error("Scalar is fixed.");

    if (Bundle::same_bank(hw, rd, regs[0]))
        return regs[1];
    else
        return regs[0];
}

FlagRegister VirtualFlag::toPhysical() const {
    if (n == 2)
        return FlagRegister(idx >> 1);
    else
        return FlagRegister::createFromIndex(idx);
}

VirtualFlag VirtualFlagAllocator::allocVirtual(int n) {
    if (!free) throw out_of_registers_exception();
    if (n > 2) stub();

    uint32_t bmask = (n == 2) ? 0x55555555 : 0xFFFFFFFF;
    int base = bsf(free & bmask);

    VirtualFlag vflag {base, n};
    claim(vflag);

    return vflag;
}

FlagRegister VirtualFlagAllocator::alloc(int n) {
    auto vflag = allocVirtual(n);
    if (isVirtual(vflag)) throw out_of_registers_exception();

    lock(vflag);

    return vflag.toPhysical();
}

FlagRegister VirtualFlagAllocator::assignPhysical(VirtualFlag vflag) {
    VirtualFlag pflag;

    // Is it already a physical flag register?
    if (!isVirtual(vflag)) {
        pflag = vflag;
    } else {
        // It's virtual. Starting at nextPhys, find an unlocked flag register.
        for (int i = nextPhys; i < nextPhys + nflag; i++) {
            if (i & (vflag.n - 1)) continue;
            auto idx = i & (nflag - 1);
            if (!(locked & mask(idx, vflag.n))) {
                nextPhys = (idx + vflag.n) & (nflag - 1);
                pflag = VirtualFlag {idx, vflag.n};
                break;
            }
        }
    }

    if (!pflag) throw out_of_registers_exception();

    return pflag.toPhysical();
}

static inline RegData getMaskFlag(VirtualFlag vflag, CommonState &state) {
    if (state.vflagStorage.isValid())
        return state.vflagStorage[vflag.idx].reinterpret(
                0, vflag.n == 2 ? DataType::ud : DataType::uw);
    else if (!state.raVFlag.isVirtual(vflag)) {
        auto pflag = vflag.toPhysical();
        state.usePhysicalFlag(pflag);
        return pflag;
    } else
        throw need_vflag();
}

template <HW hw>
FlagRegister gemm_kernel_generator_t<hw>::getPhysicalFlag(
        VirtualFlag vflag, CommonState &state) {
    VirtualFlag pflag;

    if (state.vflagStorage.isValid()) {
        // Check if virtual flag is currently active.
        int pidx = -1;
        for (int i = 0; i < FlagRegister::subcount(hw); i++)
            if (state.activeVFlags[i] == vflag) pidx = i;

        // If flag is not currently active, load it into a physical flag.
        if (pidx == -1) {
            auto freg = state.raVFlag.assignPhysical(vflag);
            pidx = freg.index();
            mov(1, freg, getMaskFlag(vflag, state));
            for (int i = 0; i < int(vflag.n); i++)
                state.activeVFlags[pidx + i] = vflag;
        }

        pflag = VirtualFlag {pidx, vflag.n};
    } else {
        if (state.raVFlag.isVirtual(vflag)) throw need_vflag();

        pflag = vflag;
    }

    return pflag.toPhysical();
}

template <HW hw>
void gemm_kernel_generator_t<hw>::allocVFlagStorage(
        const CommonStrategy &strategy, CommonState &state) {
    state.vflagStorage
            = state.ra.alloc(getHint(HintType::LongTerm, strategy)).uw();
}

/************************/
/* Pseudo-instructions. */
/************************/

// goto instruction with Xe semantics.
template <HW hw>
void gemm_kernel_generator_t<hw>::goto12(const InstructionModifier &mod,
        ngen::Label &jip, ngen::Label &uip, bool branchCtrl) {
    InstructionModifier mmod = mod;
    if (!isXe && !branchCtrl) {
        if (mmod.getPredCtrl() == PredCtrl::None) stub();
        mmod.setPredInv(!mmod.isPredInv());
    }
    goto_(mmod, jip, uip, branchCtrl);
}

// Compare to zero.
template <HW hw>
void gemm_kernel_generator_t<hw>::cmp0(
        const InstructionModifier &mod, RegData src0) {
    mov(mod, null.retype(src0.getType()), abs(src0));
}

// Scale then add: dst <- src0 + src1 * (numerator / denominator), rounding up.
// If exact = true, ensure src1 * num / denom is integral if src1 immediate.
template <HW hw>
void gemm_kernel_generator_t<hw>::addScaled(const InstructionModifier &mod,
        const RegData &dst, int src0, const RegData &src1, int numerator,
        int denominator, CommonState &state, bool exact) {
    if (!is_zero_or_pow2(numerator)) stub();
    if (!is_zero_or_pow2(denominator)) stub();

    if (numerator == denominator) {
        (src0 != 0) ? add(mod, dst, src1, src0)
                    : (src1 != dst) ? mov(mod, dst, src1) : noop();
    } else if (numerator > denominator) {
        (src0 == 0) ? mulConstant(mod, dst, src1, numerator / denominator)
                    : mad(mod, dst, src0, src1, numerator / denominator);
    } else if ((numerator * 2) == denominator)
        avg(mod, dst, src1, src0 * 2);
    else {
        add(mod, dst, src1, ((src0 + 1) * denominator / numerator) - 1);
        asr(mod, dst, dst, log2(denominator) - log2(numerator));
    }
}

template <HW hw>
void gemm_kernel_generator_t<hw>::addScaled(const InstructionModifier &mod,
        const RegData &dst, const RegData &src0, const RegData &src1,
        int numerator, int denominator, CommonState &state, bool exact) {
    if (!is_zero_or_pow2(numerator)) stub();
    if (!is_zero_or_pow2(denominator)) stub();

    if (numerator == denominator)
        add(mod, dst, src1, src0);
    else if (numerator > denominator)
        mad(mod, dst, src0, src1, numerator / denominator);
    else {
        auto temp = state.ra.alloc_sub(src1.getType());
        if (exact)
            asr(mod, temp, src1, log2(denominator) - log2(numerator));
        else {
            add(mod, temp, src1, (denominator / numerator) - 1);
            asr(mod, temp, temp, log2(denominator) - log2(numerator));
        }
        add(mod, dst, temp, src0);
        state.ra.safeRelease(temp);
    }
}

template <HW hw>
void gemm_kernel_generator_t<hw>::addScaled(const InstructionModifier &mod,
        const RegData &dst, const RegData &src0, int src1, int numerator,
        int denominator, CommonState &state, bool exact) {
    if (!is_zero_or_pow2(numerator)) stub();
    if (!is_zero_or_pow2(denominator)) stub();
    if (exact && ((numerator * src1) % denominator))
        throw std::runtime_error("Misaligned immediate value.");
    add(mod, dst, src0, (numerator * src1) / denominator);
}

// Synchronize on all pipes and OOO operations.
template <HW hw>
void gemm_kernel_generator_t<hw>::syncall() {
    if (hw == HW::Xe_LP) sync.allwr(SWSB(1));
}

// Multiply by a constant, optimizing for power-of-2 constants.
template <HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::mulConstant(const InstructionModifier &mod,
        const RegData &dst, const RegData &src0, int32_t src1) {
    if (src1 == 0)
        mov<DT>(mod, dst, uint16_t(0));
    else if (src1 == 1) {
        if (dst != src0) mov<DT>(mod, dst, src0);
    } else if (src1 == -1)
        mov<DT>(mod, dst, -src0);
    else if (is_zero_or_pow2(src1))
        shl<DT>(mod, dst, src0, uint16_t(log2(src1)));
    else if (src1 >= 0x10000)
        mul<DT>(mod, dst, src0, uint32_t(src1));
    else if (src1 < -0x8000)
        mul<DT>(mod, dst, src0, int32_t(src1));
    else if (src1 > 0)
        mul<DT>(mod, dst, src0, uint16_t(src1));
    else
        mul<DT>(mod, dst, src0, int16_t(src1));
}

// Three-argument add.
template <HW hw>
template <typename DT, typename S0, typename S2>
void gemm_kernel_generator_t<hw>::eadd3(const InstructionModifier &mod,
        const RegData &dst, const S0 &src0, const RegData &src1,
        const S2 &src2) {
    add<DT>(mod, dst, src1, src0);
    add<DT>(mod, dst, dst, src2);
}

template <HW hw>
template <typename S0, typename S2>
void gemm_kernel_generator_t<hw>::emad(const InstructionModifier &mod,
        const RegData &dst, const S0 &src0, const RegData &src1, const S2 &src2,
        const CommonStrategy &strategy, CommonState &state) {
    auto dstType = dst.getType();
    if ((hw >= HW::Gen10 && !(dst.getOffset() & 1)
                && !one_of(dstType, DataType::q, DataType::uq)
                && !one_of(src2.getType(), DataType::d, DataType::ud))
            || one_of(dstType, DataType::hf, DataType::f, DataType::df)) {
        mad(mod, dst, src0, src1, src2);
    } else {
        auto ttype = (isSigned(src1.getType()) || isSigned(src2.getType()))
                ? DataType::d
                : DataType::ud;
        auto temp = state.ra.alloc_sub(ttype);
        emul(mod, temp, src1, src2, strategy, state);
        eadd(mod, dst, dst, temp, strategy, state);
        state.ra.safeRelease(temp);
    }
}

template <HW hw>
template <typename S0>
void gemm_kernel_generator_t<hw>::emad(const InstructionModifier &mod,
        const RegData &dst, const S0 &src0, const RegData &src1, int32_t src2,
        const CommonStrategy &strategy, CommonState &state) {
    auto dstType = dst.getType();
    if (hw >= HW::Gen10 && !(dst.getOffset() & 1)
            && (src2 >= -0x8000 && src2 < 0x10000)
            && !one_of(dstType, DataType::q, DataType::uq)) {
        mad(mod, dst, src0, src1, src2);
    } else {
        auto ttype = isSigned(src1.getType()) ? DataType::d : DataType::ud;
        auto temp = state.ra.alloc_sub(ttype);
        emulConstant(mod, temp, src1, src2, strategy, state);
        eadd(mod, dst, dst, temp, strategy, state);
        state.ra.safeRelease(temp);
    }
}

template <HW hw>
void gemm_kernel_generator_t<hw>::ejmpi(InstructionModifier mod, Label &dst) {
    jmpi(mod, dst);
}

/********************/
/* Utility routines */
/********************/

// Modulo by constant value.
template <ngen::HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::mod(const ngen::Subregister &dst,
        const ngen::Subregister &src, uint16_t modulus,
        const CommonStrategy &strategy, CommonState &state) {
    if (is_zero_or_pow2(modulus))
        and_<DT>(1, dst, src, modulus - 1);
    else if (strategy.emulate.emulate64 && (hw <= HW::Xe_LP))
        math<DT>(1, MathFunction::irem, dst, src, modulus);
    else {
        alignDown<DT>(dst, src, modulus, strategy, state);
        add<DT>(1, dst, src, -dst);
    }
}

// Return both (a % b) and a - (a % b).
template <ngen::HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::modExt(const ngen::Subregister &dstMod,
        const ngen::Subregister &dstMultiple, const ngen::Subregister &src,
        uint16_t modulus, const CommonStrategy &strategy, CommonState &state) {
    if (is_zero_or_pow2(modulus)) {
        and_<DT>(1, dstMultiple, src, ~uint32_t(modulus - 1));
        and_<DT>(1, dstMod, src, modulus - 1);
    } else if (strategy.emulate.emulate64 && (hw <= HW::Xe_LP)) {
        math<DT>(1, MathFunction::irem, dstMod, src, modulus);
        add<DT>(1, dstMultiple, src, -dstMod);
    } else {
        alignDown<DT>(dstMultiple, src, modulus, strategy, state);
        add<DT>(1, dstMod, src, -dstMultiple);
    }
}

// Align an unsigned value down to a multiple of align.
template <ngen::HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::alignDown(const ngen::Subregister &dst,
        const ngen::Subregister &src, uint16_t align,
        const CommonStrategy &strategy, CommonState &state) {
    if (is_zero_or_pow2(align))
        and_<DT>(1, dst, src, uint32_t(-align));
    else if (strategy.emulate.emulate64 && (hw <= HW::Xe_LP)) {
        auto rem = state.ra.alloc_sub<uint32_t>();
        math<DT>(1, MathFunction::irem, rem, src, uint32_t(align));
        add<DT>(1, dst, src, -rem);
        state.ra.safeRelease(rem);
    } else {
        // Replace integer division with multiplication by reciprocal + shift.
        // Valid for numerators <= 2^31.
        int shift = ngen::utils::bsr(align);
        uint32_t recip32
                = ((uint64_t(0x100000000) << shift) + align - 1) / align;
        bool emulate = strategy.emulate.emulate64;
        if (emulate) {
            auto temp = state.ra.alloc_sub<uint32_t>();
            emul32High(1, temp, src, recip32);
            shr(1, temp, temp, shift);
            mul(1, dst, temp, align);
            state.ra.safeRelease(temp);
        } else {
            auto temp = state.ra.alloc_sub<uint64_t>();
            auto tempHi = temp.ud(1);
            mul(1, temp, src, recip32);
            shr(1, tempHi, tempHi, shift);
            mul(1, dst, tempHi, align);
            state.ra.safeRelease(temp);
        }
    }
}

// Align an unsigned value up to a multiple of align.
template <ngen::HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::alignUp(const ngen::Subregister &dst,
        const ngen::Subregister &src, uint16_t align,
        const CommonStrategy &strategy, CommonState &state) {
    add<DT>(1, dst, src, uint16_t(align - 1));
    alignDown<DT>(dst, dst, align, strategy, state);
}

// Non-constant integer division.
// Requires an auxiliary constant: ceiling(2^(32 + s) / denom), where s = floor(log2(denom)).
template <HW hw>
template <typename DT>
void gemm_kernel_generator_t<hw>::divDown(const Subregister &dst,
        const Subregister &src0, const Subregister &src1,
        const Subregister &src1Recip, const FlagRegister &flag,
        const CommonStrategy &strategy, CommonState &state) {
    auto shift = state.ra.alloc_sub<uint16_t>();
    auto pop = state.ra.alloc_sub<uint16_t>();
    cbit(1, pop, src1);
    fbh(1, shift, src1);
    cmp(1 | gt | flag, pop, 1);
    add(1, shift, -shift, 31);
    emul32High(1 | flag, dst, src0, src1Recip);
    shr(1 | ~flag, dst, src0, shift);
    shr(1 | flag, dst, dst, shift);
    state.ra.safeRelease(shift);
    state.ra.safeRelease(pop);
}

// Simple do-while loop macro for the backward conditional branch at end of loop.
template <HW hw>
void gemm_kernel_generator_t<hw>::simtDoWhileLoop(
        const InstructionModifier &mod, Label &dest) {
    Label next;

    goto12(mod, next, dest, true);
    mark(next);
    join(mod.getExecSize());
}

// Barrier with SLM fence.
template <HW hw>
void gemm_kernel_generator_t<hw>::slmBarrier(
        const GRF &temp, const GRF &r0_info) {
    if (hw >= HW::Gen11) {
        slmfence(temp, r0_info);
        if (hw < HW::Xe_LP) mov<uint32_t>(8, null, temp);
    }
    barrier(temp, r0_info);
}

// Create a copy of a scalar subregister in the other bank.
template <HW hw>
template <typename T>
void gemm_kernel_generator_t<hw>::duplicateScalar(
        Scalar<T> &val, CommonState &state) {
    if (!val.fixed()) {
        auto reg0 = val.getReg(0);
        auto bundle = Bundle::locate(hw, reg0);
        auto reg1 = state.ra.alloc_sub(
                reg0.getType(), Bundle(bundle.bank_id ^ 1, Bundle::any));

        mov(1, reg1, reg0);
        val = Scalar<T>(reg0, reg1);
    }
}

// Create multiple versions of the input subregister reg, shifted by amounts specified by the shifts bitmask.
// The input subregister is used for one of the versions.
template <HW hw>
MultishiftSubregister gemm_kernel_generator_t<hw>::multishift(
        const Subregister &reg, unsigned int shifts,
        const CommonStrategy &strategy, CommonState &state, Bundle hint) {
    MultishiftSubregister ms;

    while (shifts != 0) {
        int shift = bsr(shifts);
        shifts &= ~(1 << shift);

        if (shifts != 0) {
            Subregister s = state.ra.alloc_sub(reg.getType(), hint);
            ms.set(shift, s);
            eshr(1, s, reg, shift, strategy, state);
        } else {
            ms.set(shift, reg);
            if (shift > 0) eshr(1, reg, reg, shift, strategy, state);
        }
    }

    return ms;
}

// Get ID of fused thread (0/1), multiplied by a scaling factor. Assumes r1 has not been overwritten.
template <HW hw>
void gemm_kernel_generator_t<hw>::getFusedID(int scale,
        const CommonProblem &problem, const CommonStrategy &strategy,
        CommonState &state) {
    if (problem.fused) {
        state.fusedID = state.ra.alloc_sub<uint16_t>(
                getHint(HintType::LongTerm, strategy));
        if (is_zero_or_pow2(scale)) {
            int shift = log2(scale) - log2(strategy.subgroupSize);
            Subregister lid0 = r1.uw(0);

            if (shift > 0)
                shl(1, state.fusedID, lid0, uint16_t(shift));
            else if (shift < 0)
                shr(1, state.fusedID, lid0, uint16_t(-shift));

            and_(1, state.fusedID, (shift == 0) ? lid0 : state.fusedID,
                    uint16_t(scale));
        } else {
            shr(1, state.fusedID, r1.uw(0),
                    uint16_t(log2(strategy.subgroupSize)));
            and_(1, state.fusedID, state.fusedID, uint16_t(1));
            mulConstant(1, state.fusedID, state.fusedID, uint16_t(scale));
        }
    }
}

// Move r0 information to another register if configured.
template <HW hw>
void gemm_kernel_generator_t<hw>::moveR0(
        const CommonStrategy &strategy, CommonState &state) {
    if (state.r0_info.isInvalid()) {
        switch (strategy.moveR0) {
            case MoveR0::None: state.r0_info = r0.ud(); return;
            case MoveR0::Acc: state.r0_info = acc0.ud(); break;
            case MoveR0::Addr: state.r0_info = a0.ud(); break;
            case MoveR0::GRF:
                state.r0_info
                        = state.ra.alloc(getHint(HintType::R0Info, strategy));
                break;
        }
    }

    mov<uint32_t>(8, state.r0_info, r0);

    if (!strategy.sipR0WA) state.ra.release(r0);
}

template <HW hw>
void gemm_kernel_generator_t<hw>::moveR0(
        const GEMMStrategy &strategy, GEMMState &state) {
    if (strategy.moveR0 == MoveR0::GRF) {
        if (strategy.registerScheme == GEMMStrategy::ACB
                || strategy.registerScheme == GEMMStrategy::BCA) {
            state.r0_info = r127;
            state.ra.claim(r127);
        }
    }
    moveR0(static_cast<CommonStrategy>(strategy), state);
}

// Divide out subgroup size from x local size and local ID.
template <HW hw>
void gemm_kernel_generator_t<hw>::removeSG(const CommonProblem &problem,
        const CommonStrategy &strategy, const CommonState &state) {
    if (problem.wgSupport) {
        uint16_t sss = log2(strategy.subgroupSize);

        auto localSize0 = interface.getLocalSize(0);
        auto localID0 = interface.getLocalID(0);

        shr(1, localSize0, localSize0, sss);
        shr(1, localID0.uw(0), localID0.uw(0), sss);
    }
}

// Swap bit 0 of local ID x and y if needed so that threads are ordered according to specified EU fusion.
template <HW hw>
void gemm_kernel_generator_t<hw>::reorderFusedEUs(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    if (!problem.fused) return;

    if (strategy.loopOrder[0] != problem.fusedLoop) {
        auto temp = state.ra.alloc_sub<uint32_t>();
        and_(1, temp, state.inputs.localIDN.ud(), uint16_t(1));
        bfi2(1, state.inputs.localIDN.ud(), uint16_t(1),
                state.inputs.localIDM.ud(), state.inputs.localIDN.ud());
        bfi2(1, state.inputs.localIDM.ud(), uint16_t(1), temp,
                state.inputs.localIDM.ud());
        state.ra.safeRelease(temp);
    }
}

template <HW hw>
Subregister gemm_kernel_generator_t<hw>::copySubregister(
        const Subregister &reg, CommonState &state, Bundle hint) {
    auto copy = state.ra.alloc_sub(reg.getType(), hint);
    mov(1, copy, reg);
    return copy;
}

static inline bool canDualGRF(
        HW hw, DataType dt, const CommonStrategy &strategy) {
    return (strategy.dualGRF && (elementsPerGRF(hw, dt) < 32));
}

// Perform a binary register-wise operation.
template <typename F>
static inline void map(HW hw, DataType dt, const GRFMultirange &r1,
        const GRFMultirange &r2, const CommonStrategy &strategy, F f) {
    int ne = elementsPerGRF(hw, dt);
    int rstride = canDualGRF(hw, dt, strategy) ? 2 : 1;
    int len = r1.getLen();

    for (int rr = 0; rr < len;) {
        int nr = std::min<int>(len - rr, rstride);
        if (!r1.contiguous(rr, nr) || !r2.contiguous(rr, nr)) nr = 1;
        f(nr * ne, r1[rr].retype(dt), r2[rr].retype(dt));
        rr += nr;
    }
}

// Perform a ternary register-wise operation.
template <typename F>
static inline void map(HW hw, DataType dt, const GRFMultirange &r1,
        const GRFMultirange &r2, const GRFMultirange &r3,
        const CommonStrategy &strategy, F f) {
    int ne = elementsPerGRF(hw, dt);
    int rstride = canDualGRF(hw, dt, strategy) ? 2 : 1;
    int len = r1.getLen();

    for (int rr = 0; rr < len;) {
        int nr = std::min<int>(len - rr, rstride);
        if (!r1.contiguous(rr, nr) || !r2.contiguous(rr, nr)) nr = 1;
        f(nr * ne, r1[rr].retype(dt), r2[rr].retype(dt), r3[rr].retype(dt));
        rr += nr;
    }
}

// Perform a unary register-wise operation on a register block.
template <typename F>
static inline void map(HW hw, DataType dt, const GRFMultirange &regs,
        const vector<RegisterBlock> &layout, const CommonStrategy &strategy,
        F f) {
    int curOff = 0, curBytes = 0;
    auto ebytes = getBytes(dt);

    auto map1 = [&]() {
        curOff &= -ebytes;
        curBytes &= -ebytes;
        while (curBytes) {
            int maxBytes;
            if (curOff & (GRF::bytes(hw) - 1))
                maxBytes = GRF::bytes(hw) - curOff;
            else
                maxBytes = (canDualGRF(hw, dt, strategy) ? 2 : 1)
                        * GRF::bytes(hw);

            auto nbytes = rounddown_pow2(std::min(maxBytes, curBytes));
            auto ne = std::min<int>(32, nbytes / ebytes);
            nbytes = ne * ebytes;

            auto reg = regs[curOff >> GRF::log2Bytes(hw)].sub(
                    (curOff & (GRF::bytes(hw) - 1)) / ebytes, dt)(1);

            f(ne, reg);

            curBytes -= nbytes;
            curOff += nbytes;
        }
    };

    for (auto &block : layout) {
        if (block.offsetBytes == curOff + curBytes)
            curBytes += block.bytes;
        else {
            map1();
            curOff = block.offsetBytes;
            curBytes = block.bytes;
        }
    }

    map1();
}

template <typename T, typename F>
static inline void map(HW hw, const GRFMultirange &r1, const GRFMultirange &r2,
        const CommonStrategy &strategy, F f) {
    map(hw, getDataType<T>(), r1, r2, strategy, f);
}

template <typename T, typename F>
static inline void map(HW hw, const GRFMultirange &r1, const GRFMultirange &r2,
        const GRFMultirange &r3, const CommonStrategy &strategy, F f) {
    map(hw, getDataType<T>(), r1, r2, r3, strategy, f);
}

template <typename T, typename F>
static inline void map(HW hw, const GRFMultirange &regs,
        const vector<RegisterBlock> &layout, const CommonStrategy &strategy,
        F f) {
    map(hw, getDataType<T>(), regs, layout, strategy, f);
}

template <typename... Targs>
static inline void map(HW hw, Type T, Targs... args) {
    map(hw, T.ngen(), args...);
}

// Move subregister to another pipe.
static inline void movePipes(Subregister &s, bool sizeCanChange = true) {
    DataType type = s.getType();

    switch (type) {
        case DataType::hf: type = DataType::uw; break;
        case DataType::f: type = DataType::ud; break;
        case DataType::df:
            if (sizeCanChange) type = DataType::ud;
            break;
        case DataType::w:
        case DataType::uw: type = DataType::hf; break;
        case DataType::d:
        case DataType::ud: type = DataType::f; break;
        case DataType::q:
        case DataType::uq:
            if (sizeCanChange) type = DataType::f;
            break;
        default: break;
    }

    s = s.reinterpret(0, type);
}

// Move register region to integer pipe.
static inline void moveToIntPipe(int esize, RegData &s) {
    switch (s.getType()) {
        case DataType::hf: s.setType(DataType::uw); break;
        case DataType::q:
        case DataType::uq:
        case DataType::f: s.setType(DataType::ud); break;
        case DataType::df:
            s.setType(DataType::uq);
            EmulationImplementation::makeDWPair(s, esize);
            break;
        default: break;
    }
}

// Set a matrix to zero.
template <HW hw>
void gemm_kernel_generator_t<hw>::zeroMatrix(
        const GRFMultirange &r, const CommonStrategy &strategy) {
    map<uint32_t>(hw, r, r, strategy,
            [&](int esize, GRF reg, GRF _) { mov(esize, reg, uint16_t(0)); });
}

// Release fused remainder-related state variables.
template <HW hw>
void gemm_kernel_generator_t<hw>::releaseFusedRemainders(GEMMState &state) {
    state.ra.safeRelease(state.remFusedStorage);
    state.remaindersFused[LoopM] = Subregister {};
    state.remaindersFused[LoopN] = Subregister {};
}

template <HW hw>
void gemm_kernel_generator_t<hw>::saveLocalIDs(
        const GEMMStrategy &strategy, GEMMState &state) {
    state.lidStorage = state.ra.alloc_sub<uint32_t>(
            getHint(HintType::LongTerm, strategy));
    state.lidM = state.lidStorage.uw(0);
    state.lidN = state.lidStorage.uw(1);
    mov(1, state.lidM, state.inputs.localIDM);
    mov(1, state.lidN, state.inputs.localIDN);
}

template <HW hw>
void gemm_kernel_generator_t<hw>::releaseSavedLocalIDs(GEMMState &state) {
    state.ra.safeRelease(state.lidStorage);
    state.lidStorage = invalid;
    state.lidM = invalid;
    state.lidN = invalid;
}

// Clear read suppresion data on ALU pipes.
template <HW hw>
void gemm_kernel_generator_t<hw>::doReadSuppressionWA(
        const CommonStrategy &strategy, CommonState &state) {
    GRF temp;
    bool freeTemp = false;

    if (!strategy.readSuppressionWA) return;

    if (state.r0_info.isValid() && !state.r0_info.isARF())
        temp = GRF(state.r0_info.getBase());
    else {
        temp = state.ra.try_alloc();
        if (temp.isValid())
            freeTemp = true;
        else
            temp = r0;
    }

    csel<int16_t>(8, temp, temp, temp, temp);
    csel<float>(8, temp, temp, temp, temp);

    if (freeTemp) state.ra.safeRelease(temp);
}

// Common register allocator hints.
template <ngen::HW hw>
Bundle gemm_kernel_generator_t<hw>::getHint(HintType type) {
    switch (type) {
        case HintType::Bank0: return Bundle(0, Bundle::any);
        case HintType::Bank1: return Bundle(1, Bundle::any);
        default: break;
    }

    switch (hw) {
        case HW::Gen9:
        case HW::Gen10:
        case HW::Gen11:
            switch (type) {
                case HintType::TempComp0: return Bundle(0, 1);
                case HintType::TempComp1: return Bundle(1, 1);
                case HintType::Bank0: return Bundle(0, Bundle::any);
                case HintType::Bank1: return Bundle(1, Bundle::any);
                case HintType::LongTerm: return Bundle(Bundle::any, 0);
                default: break;
            }
            break;
        default: break;
    }

    return Bundle();
}

template <ngen::HW hw>
Bundle gemm_kernel_generator_t<hw>::getHint(
        HintType type, const CommonStrategy &strategy) {
    return getHint(type);
}

// GEMM register allocation hints.
template <ngen::HW hw>
Bundle gemm_kernel_generator_t<hw>::getHint(
        HintType type, const GEMMStrategy &strategy) {
    switch (hw) {
        case HW::Gen9:
        case HW::Gen10:
        case HW::Gen11:
            switch (strategy.registerScheme) {
                case GEMMStrategy::CSeparate:
                    switch (type) {
                        case HintType::A0Broadcast:
                        case HintType::A0: return Bundle(1, 0);
                        case HintType::A1Broadcast:
                        case HintType::A1: return Bundle(0, 0);
                        case HintType::B0Broadcast:
                        case HintType::B0: return Bundle(0, 0);
                        case HintType::B1Broadcast:
                        case HintType::B1: return Bundle(1, 0);
                        case HintType::C: return Bundle(0, 1);
                        case HintType::CLoad: return Bundle(1, 0);
                        default: break;
                    }
                    break;
                case GEMMStrategy::ACB:
                    switch (type) {
                        case HintType::A0Broadcast:
                        case HintType::A0: return Bundle(1, 0);
                        case HintType::A1Broadcast:
                        case HintType::A1: return Bundle(0, 0);
                        case HintType::B0Broadcast:
                        case HintType::B0: return Bundle(0, 1);
                        case HintType::B1Broadcast:
                        case HintType::B1: return Bundle(1, 1);
                        case HintType::C: return Bundle(0, 0);
                        case HintType::CLoad: return Bundle();
                        default: break;
                    }
                    break;
                case GEMMStrategy::BCA:
                    switch (type) {
                        case HintType::A0Broadcast:
                        case HintType::A0: return Bundle(0, 1);
                        case HintType::A1Broadcast:
                        case HintType::A1: return Bundle(1, 1);
                        case HintType::B0Broadcast:
                        case HintType::B0: return Bundle(1, 0);
                        case HintType::B1Broadcast:
                        case HintType::B1: return Bundle(0, 0);
                        case HintType::C: return Bundle(0, 0);
                        case HintType::CLoad: return Bundle();
                        default: break;
                    }
                    break;
                default: break;
            }
            break;
        case HW::Xe_LP:
            switch (strategy.registerScheme) {
                case GEMMStrategy::CSeparate:
                    switch (type) {
                        case HintType::A0Broadcast:
                        case HintType::A0: return Bundle(1, Bundle::any);
                        case HintType::A1Broadcast:
                        case HintType::A1: return Bundle(0, Bundle::any);
                        case HintType::B0Broadcast:
                        case HintType::B0: return Bundle(0, Bundle::any);
                        case HintType::B1Broadcast:
                        case HintType::B1: return Bundle(1, Bundle::any);
                        case HintType::C: return Bundle(0, 0);
                        case HintType::CLoad: return Bundle(1, Bundle::any);
                        default: break;
                    }
                    break;
                case GEMMStrategy::ACB:
                case GEMMStrategy::BCA:
                case GEMMStrategy::VNC:
                    switch (type) {
                        case HintType::A0:
                        case HintType::B0: return Bundle(1, Bundle::any);
                        case HintType::A1:
                        case HintType::B1: return Bundle(0, Bundle::any);
                        case HintType::A0Broadcast:
                        case HintType::B0Broadcast:
                            return Bundle(0, Bundle::any);
                        case HintType::A1Broadcast:
                        case HintType::B1Broadcast:
                            return Bundle(1, Bundle::any);
                        case HintType::C: return Bundle(0, Bundle::any);
                        default: break;
                    }
                    break;
                case GEMMStrategy::ABInterleave:
                    switch (type) {
                        case HintType::A0:
                        case HintType::A1:
                        case HintType::A0Broadcast:
                        case HintType::A1Broadcast: return Bundle(1, 0);
                        case HintType::B0:
                        case HintType::B1:
                        case HintType::B0Broadcast:
                        case HintType::B1Broadcast: return Bundle(1, 4);
                        case HintType::C: return Bundle(0, Bundle::any);
                        default: break;
                    }
                    break;
            }
            break;
        default: break;
    }

    return getHint(type);
}

// Copy kernel register allocation hints.
template <ngen::HW hw>
Bundle gemm_kernel_generator_t<hw>::getHint(
        HintType type, const CopyStrategy &strategy) {
    switch (hw) {
        case HW::Gen9:
        case HW::Gen10:
        case HW::Gen11:
        case HW::Xe_LP:
            switch (type) {
                case HintType::S: return Bundle();
                case HintType::D: return Bundle();
                case HintType::SAddr: return Bundle();
                case HintType::DAddr: return Bundle();
                default: break;
            }
            break;
        default: break;
    }

    return getHint(type);
}

static inline void safeReleaseRanges(
        vector<GRFRange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        state.ra.safeRelease(a);
    ranges.clear();
}

static inline void releaseRanges(vector<GRFRange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        state.ra.release(a);
}

static inline void reclaimRanges(vector<GRFRange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        state.ra.claim(a);
}

static inline void safeReleaseRanges(
        GRFMultirange &ranges, CommonState &state) {
    safeReleaseRanges(ranges.ranges, state);
    ranges.ranges.clear();
}

static inline void safeReleaseRanges(
        vector<GRFMultirange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        safeReleaseRanges(a, state);
    ranges.clear();
}

static inline void releaseRanges(GRFMultirange &ranges, CommonState &state) {
    releaseRanges(ranges.ranges, state);
}

static inline void releaseRanges(
        vector<GRFMultirange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        releaseRanges(a, state);
}

static inline void reclaimRanges(GRFMultirange &ranges, CommonState &state) {
    reclaimRanges(ranges.ranges, state);
}

// Reclaim a list of GRF multiranges.
static inline void reclaimRanges(
        vector<GRFMultirange> &ranges, CommonState &state) {
    for (auto &a : ranges)
        reclaimRanges(a, state);
}

/***********************\
|* Load/store support. *|
\***********************/

static bool needsPseudoblock(HW hw, Type T, int r, int c,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, bool writable, bool masked) {
    bool dwAligned = (atype.alignment & 0x3) == 0;
    bool owAligned = (atype.alignment & 0xF) == 0;
    bool pseudo = !dwAligned || ((r * c * T) & 0x3) || (writable && !owAligned)
            || (masked && !owAligned && (atype.base.getModel() != ModelA64))
            || astrategy.atomic
            || (isColMajor(atype.layout) ? c : r) % atype.crosspack
            || ((atype.base.getModel() == ModelSLM)
                    && (hw < HW::Gen11 || !owAligned));

    return pseudo;
}

static bool pseudoblockUseSurface(
        const MatrixAddressing &atype, const RegisterBlock &block) {
    return (atype.base.getModel() == ModelSLM) && (block.ebytes == 4);
}

// Get effective access type to use when setting up addresses.
static AccessType effectiveAccessType(AccessType type,
        const MatrixAddressing &atype, const RegisterBlock &block) {
    if (type == AccessType::Block && block.ebytes < 16 && block.extra)
        type = AccessType::PseudoBlock;
    else if (type == AccessType::Scattered && atype.base.getModel() == ModelSLM
            && block.ebytes == 4)
        type = AccessType::ChannelScattered;
    else if (type == AccessType::ChannelScattered && block.ebytes != 4)
        type = AccessType::Scattered;
    return type;
}

// Get effective access type to use when performing loads/stores.
static AccessType implAccessType(AccessType type, const MatrixAddressing &atype,
        const RegisterBlock &block) {
    type = effectiveAccessType(type, atype, block);
    if (type == AccessType::PseudoBlock)
        type = pseudoblockUseSurface(atype, block)
                ? AccessType::ChannelScattered
                : AccessType::Scattered;
    return type;
}

// Count the number of address/header GRFs required by a RegisterBlock.
static inline int addrGRFCount(const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, const RegisterBlock &block) {
    // Non-load blocks don't get address registers.
    if (!block.isLoadBlock()) return 0;

    switch (effectiveAccessType(astrategy.accessType, atype, block)) {
        case AccessType::Scattered:
        case AccessType::ChannelScattered:
        case AccessType::PseudoBlock: {
            auto bytesPerAddr = (atype.base.getModel() == ModelA64) ? 8 : 4;
            auto baseSIMD = std::max<int>(block.simdSize, 8);
            auto log2Bytes = block.log2GRFBytes;
            return (bytesPerAddr * baseSIMD + (1 << log2Bytes) - 1)
                    >> log2Bytes;
        }
        case AccessType::Block: return 1;
    }
    throw std::runtime_error("Invalid addressing.");
}

// Allocate address registers for a layout.
static void allocAddrRegs(vector<GRFRange> &addrRegs,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, CommonState &state,
        Bundle hint = Bundle()) {
    auto nblocks = int(layout.size());

    addrRegs.resize(nblocks);

    for (int l = 0; l < nblocks; l++)
        addrRegs[l] = state.ra.alloc_range(
                addrGRFCount(atype, astrategy, layout[l]), hint);
}

// Check if a layout is completely column-major.
static inline bool isLayoutColMajor(const vector<RegisterBlock> &layout) {
    if (layout.size() == 0) throw std::runtime_error("Empty layout.");
    return layout[0]
            .colMajor; // All layouts we create are homogeneous currently.
}

// Get the matrix size represented by a layout.
static inline void getLayoutDims(
        const vector<RegisterBlock> &layout, int &m, int &n) {
    // For now all layouts are sorted so last block is in lower-right corner.
    auto &last = layout[layout.size() - 1];
    m = last.offsetR + last.nr;
    n = last.offsetC + last.nc;
}

// Check if every block in a layout has the given crosspack, with no padding.
static inline bool hasFullCrosspack(
        const vector<RegisterBlock> &layout, int crosspack) {
    if (layout.size() == 0) return true;
    if (layout[0].crosspack
            != crosspack) // Only need to check first block of layout currently.
        return false;
    for (const auto &block : layout)
        if ((block.colMajor ? block.nc : block.nr) % crosspack) return false;
    return true;
}

// Check if the layout is tiled with the given tiling.
static inline bool hasTiling(
        const vector<RegisterBlock> &layout, int tileR, int tileC) {
    for (auto &block : layout) {
        if (tileR > 0)
            if (block.offsetR / tileR != (block.offsetR + block.nr - 1) / tileR)
                return false;
        if (tileC > 0)
            if (block.offsetC / tileC != (block.offsetC + block.nc - 1) / tileC)
                return false;
    }
    return true;
}

// Check if a layout has row fragmenting.
static bool hasRowFragmenting(const vector<RegisterBlock> &layout) {
    for (auto &block : layout)
        if (block.rowFragment) return true;
    return false;
}

// Check if a layout has column fragmenting.
static bool hasColumnFragmenting(const vector<RegisterBlock> &layout) {
    for (auto &block : layout)
        if (block.colFragment) return true;
    return false;
}

// Check if a layout has any kind of fragmenting.
static bool hasFragmenting(const vector<RegisterBlock> &layout) {
    for (auto &block : layout)
        if (block.rowFragment || block.colFragment) return true;
    return false;
}

// Check if a layout has any masking.
static bool hasMasking(const vector<RegisterBlock> &layout) {
    for (auto &block : layout)
        if (block.rowMask || block.colMask || block.flag) return true;
    return false;
}

static inline int maxScatteredSIMD(
        HW hw, const MatrixAddressingStrategy &astrategy) {
    return 16;
}

static inline int minScatteredSIMD(
        HW hw, const MatrixAddressingStrategy &astrategy) {
    return maxScatteredSIMD(hw, astrategy) >> 1;
}

// Set up a RegisterBlock structure.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getBlockInfo(Type T,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, int r, int c,
        bool remainderR, bool remainderC, bool writable, bool avoidFragment,
        ScatterSIMD smode, int maxRBlock, int maxCBlock, int &rblock,
        int &cblock, RegisterBlock &block) {
    int R = rounddown_pow2(r);
    int C = rounddown_pow2(c);

    if (maxRBlock == 0) maxRBlock = r;
    if (maxCBlock == 0) maxCBlock = c;

    // Set default parameters.
    block.colMajor = isColMajor(atype.layout);
    block.crosspack = 1;
    block.rowMask = MaskInfo::None();
    block.colMask = MaskInfo::None();
    block.rowFragment = 0;
    block.colFragment = 0;
    block.remainderR = remainderR;
    block.remainderC = remainderC;
    block.noRowsOK = false;
    block.noColsOK = false;
    block.descRemR = false;
    block.descRemC = false;
    block.descAssigned = false;
    block.addrShift = 0;
    block.writable = writable;
    block.clearFlag();
    block.log2GRFBytes = GRF::log2Bytes(hw);

    auto &vrmask = block.rowMask.variable;
    auto &vcmask = block.colMask.variable;

    auto accessType = astrategy.accessType;

    switch (accessType) {
        case AccessType::ChannelScattered:
        case AccessType::Scattered: {
            bool channelScattered
                    = (accessType == AccessType::ChannelScattered);

            // No tiling support yet.
            if (atype.tileR || atype.tileC) stub();

            // Scattered read/write messages effectively transpose DW/QW matrices.
            block.colMajor = !block.colMajor;

            // Let X be the contiguous dimension, Y the scattered dimension (in memory).
            int *xblock, *yblock;
            int maxXBlock, maxYBlock;
            int X, Y;
            bool remainderX, remainderY;
            auto &vymask = block.colMajor ? vrmask : vcmask;
            if (block.colMajor) {
                Y = R;
                X = C;
                yblock = &rblock;
                xblock = &cblock;
                maxYBlock = maxRBlock;
                maxXBlock = maxCBlock;
                remainderY = remainderR;
                remainderX = remainderC;
            } else {
                X = R;
                Y = C;
                xblock = &rblock;
                yblock = &cblock;
                maxXBlock = maxRBlock;
                maxYBlock = maxCBlock;
                remainderX = remainderR;
                remainderY = remainderC;
            }

            // Allowed accesses:
            //   A64             Essentially max 256 bytes.
            //                    8 slots x (1,2,4,8) dwords [Xe/surface: 1,2,4]
            //                    8 slots x (1,2,4) qwords
            //                   16 slots x (1,2,4) dwords
            //                   16 slots x (1,2) qwords
            //   Others           8 slots x 1 dword
            //                   16 slots x 1 dword

            // Native (col major in memory) matrix block sizes, as a result:
            //   SIMD8:          1x8  2x4 4x2 8x1      (count 1)  2x8  4x8  8x8  [others]
            //   SIMD16:         1x16 2x8 4x4 8x2 16x1 (count 1)  2x16 4x16
            // Other layouts are possible too but require dummy (non-load) blocks.
            // Only kx8 and kx16 are supported for now for {4,8}-byte types.
            // For 16-byte types, only 1x4 and 1x8 are supported.

            auto maxSIMD = maxScatteredSIMD(hw, astrategy);
            auto minSIMD = minScatteredSIMD(hw, astrategy);

            bool byte = (atype.alignment < 4) || (X * T < 4);
            bool a64 = (atype.base.getModel() == ModelA64);

            channelScattered |= byte;

            bool qword = (T.size() >= 8 && !channelScattered && a64);
            int width = qword ? 8 : 4;
            block.ebytes = byte ? 1 : width;
            block.crosspack = std::max<int>(1, width / T);
            int consecutive = std::max<int>(1, T.size() / width);

            if (block.ebytes == 4 && atype.base.getModel() == ModelSLM)
                channelScattered = true;

            // Handle source crosspack.
            int uncrosspack = 1;
            if (atype.crosspack > 1) {
                if (atype.crosspack == block.crosspack) {
                    block.crosspack = 1;
                    uncrosspack = atype.crosspack;
                } else
                    stub();
            }

            // Try to fit a native matrix block size to X and Y.
            auto slots = std::min(Y, maxYBlock) * consecutive / uncrosspack;
            if (smode == ScatterSIMD::Narrow
                    || (smode == ScatterSIMD::Default
                            && block.ebytes * minSIMD > GRF::bytes(hw))) {
                // Maximize X usage because we always have at least 2 consecutive GRFs.
                block.simdSize
                        = (slots >= maxSIMD && X <= 2) ? maxSIMD : minSIMD;
            } else {
                // Otherwise, try to maximize Y usage (larger SIMD, worse memory access).
                block.simdSize = maxSIMD;
            }
            block.simdSize
                    = std::min<int>(block.simdSize, rounddown_pow2(slots));

            bool no8x8 = isXe;
            bool simd1 = !a64 && !channelScattered;

            int hwMaxXBlock;

            if (consecutive > 1)
                hwMaxXBlock = 1;
            else if (byte)
                hwMaxXBlock = remainderX ? 1 : block.crosspack;
            else if (simd1)
                hwMaxXBlock = block.crosspack;
            else if (a64 && astrategy.atomic)
                hwMaxXBlock = block.crosspack;
            else if (channelScattered || (block.ebytes == 4 && no8x8)
                    || (block.simdSize == maxSIMD))
                hwMaxXBlock = 16 / T;
            else
                hwMaxXBlock = 32 / T;

            maxXBlock = std::min(maxXBlock, hwMaxXBlock);

            *yblock = block.simdSize * uncrosspack / consecutive;
            *xblock = std::min<int>(X, maxXBlock);
            block.count = *xblock;

            if (byte)
                block.count *= T.size();
            else
                block.count = std::max<int>(1, block.count / block.crosspack);

            // LD is determined by actual # of channels in HW. But for X = 1 we may
            //  shrink the LD to avoid allocating unnecessary registers.
            auto ldSIMD = block.simdSize;
            if (*xblock > 1 || (minSIMD * block.ebytes <= GRF::bytes(hw)))
                ldSIMD = std::max<int>(ldSIMD, minSIMD);
            block.ld = ldSIMD * uncrosspack / consecutive;

            // Handle remainder. Masking handles Y remainders.
            if (remainderY) {
                vymask.isFixed = false;
                vymask.bitRep = consecutive;
                vymask.maskRep = 1;
                vymask.rsize = *yblock;
                vymask.rdivide = 1;
            }

            // X remainders require fragmenting. Channel scattered float doesn't need complete fragmenting.
            //  Fragment 2 is possible for DWord+ types but not implemented.
            //  Similarly fragment 4/sizeof(T) possible for sub-DWord types but not implemented.
            if (remainderX) {
                auto &fragment = (block.colMajor ? block.colFragment
                                                 : block.rowFragment);
                if (channelScattered && block.crosspack == 1) {
                    fragment = std::min(*xblock, 4);
                    if (block.colMajor) // Clang can't handle the ternary operator equivalent of this.
                        block.descRemC = true;
                    else
                        block.descRemR = true;
                } else
                    fragment = 1;
            }

            block.extra = consecutive;

            // BTS scattered accesses are addressed by elements.
            if (!channelScattered && !atype.base.isStateless())
                block.addrShift = log2(block.ebytes);
            break;
        }
        case AccessType::Block:
        case AccessType::PseudoBlock: {
            // Three types of block messages:
            //    block_oword: 16 byte align, BLK masking (= dw except ow channel on R Gen9 only -- silently ignore, can't fault)
            //  aligned_oword:  4 byte align, no masking, read only
            //    block_hword: [Gen9-12LP] A64; 4 byte align R, BLKCM masking (= dw but can do ow channel on Gen9 only)
            //                             A64; 16 byte align W
            //
            // Prefer block_hword in all cases. When block_hword can't be used:
            //   Use oword if alignment can be assured (i.e. packed row/column layout, or oword-sized scalar)
            //   Otherwise, use aligned oword. load/storeMatrixBlock will emit an error if masking/stores attempted.
            //
            // Pseudoblock messages have similar layouts, but are limited to
            //  {8,16}x{dw,qw} sizes, so lengths 8,16 allowed for float, 4,8,16 for double.

            bool colMajor = block.colMajor;
            bool bytePartialCP
                    = (T.size() & 3) && ((colMajor ? C : R) % atype.crosspack);
            bool byte
                    = (atype.alignment & 3) || (R * C * T & 3) || bytePartialCP;
            bool byte1PerSlot = byte
                    && (bytePartialCP || (colMajor ? remainderR : remainderC));
            bool pseudo = (accessType == AccessType::PseudoBlock)
                    | needsPseudoblock(hw, T, R, C, atype, astrategy, writable,
                            colMajor ? remainderR : remainderC);
            int maxElements = 0;
            int maskGranularity = 1;
            int maxSIMD = maxScatteredSIMD(hw, astrategy);
            bool oword = false, aoword = false;
            int npack = 0;
            bool canQW = false;

            bool a32 = (atype.base.getModel() == ModelA32);
            bool a64 = (atype.base.getModel() == ModelA64);
            bool sc = (atype.base.getModel() == ModelSC);

            if (!pseudo && byte) return false;

            if (!pseudo) {
                int maxCount = 8;
                oword = !a64;
                aoword = ((atype.alignment & 0xF) != 0) || sc;
                block.ebytes = oword ? 16 : 32;
                maxElements = maxCount * block.ebytes / T;
                maskGranularity = 4; // Block accesses mask by dwords
            } else {
                canQW = ((R * C * T | atype.alignment) % 8 == 0);
                canQW &= !byte && a64;
                if (remainderR || remainderC) canQW &= (T.size() % 8 == 0);
                auto stride = canQW ? 8 : 4;
                auto maxNPack = byte1PerSlot ? 1 : std::max<int>(1, stride / T);
                maxElements = maxSIMD * maxNPack;
                if (T.size() > stride) maxElements = maxElements * stride / T;
            }

            auto maxABlock = maxElements / (byte1PerSlot ? 1 : atype.crosspack);

            switch (atype.layout) {
                case MatrixLayout::Pc:
                    rblock = std::min<int>(maxABlock, R);

                    if (atype.tileR)
                        rblock = std::min<int>(rblock, atype.tileR);
                    if ((atype.tileR ? atype.tileR : atype.packSize)
                            == rblock) {
                        cblock = std::min<int>(maxElements / rblock, C);
                        if (cblock < atype.crosspack
                                && isLargeCrosspack(T, atype.crosspack)) {
                            cblock = atype.crosspack;
                            rblock = std::min<int>(
                                    rblock, maxElements / cblock);
                        }
                    } else
                        cblock = atype.crosspack; // Remainder loop: no longer packed in memory

                    block.crosspack = atype.crosspack;
                    C = div_up(C, atype.crosspack);
                    break;
                case MatrixLayout::N:
                    if (atype.crosspack > 1) stub();
                    if (atype.tileR == R && R <= maxElements) {
                        cblock = std::min<int>(maxElements / R, C);
                        rblock = R;
                    } else {
                        cblock = 1;
                        rblock = std::min<int>(maxElements, R);
                    }
                    break;
                case MatrixLayout::Pr:
                    cblock = std::min<int>(maxABlock, C);

                    if (atype.tileC)
                        cblock = std::min<int>(cblock, atype.tileC);
                    if ((atype.tileC ? atype.tileC : atype.packSize)
                            == cblock) {
                        rblock = std::min<int>(maxElements / C, R);
                        if (rblock < atype.crosspack
                                && isLargeCrosspack(T, atype.crosspack)) {
                            rblock = atype.crosspack;
                            cblock = std::min<int>(
                                    cblock, maxElements / rblock);
                        }
                    } else
                        rblock = atype.crosspack;

                    block.crosspack = atype.crosspack;
                    R = div_up(R, atype.crosspack);
                    break;
                case MatrixLayout::T:
                    if (atype.crosspack > 1) stub();
                    if (atype.tileC == C && C <= maxElements) {
                        rblock = std::min<int>(maxElements / cblock, R);
                        cblock = C;
                    } else {
                        rblock = 1;
                        cblock = std::min<int>(maxElements, C);
                    }
                    break;
            }

            rblock = std::min(rblock, maxRBlock);
            cblock = std::min(cblock, maxCBlock);

            if (pseudo) {
                bool qword = canQW && (rblock * cblock * T >= 4 * maxSIMD);
                npack = std::max<int>(1, (qword ? 8 : 4) / T);
                if (byte1PerSlot) {
                    block.crosspack = npack;
                    npack = 1;
                }
                maskGranularity = qword ? 8 : byte1PerSlot ? T.size() : 4;
            }

            if (remainderR) {
                if (colMajor) {
                    // rblock cannot be more than 16 dwords = 64 bytes for masking
                    //  except for pseudo-block
                    int rblockLimit = pseudo ? rblock : 64 / T;

                    if (avoidFragment)
                        rblock = std::min<int>(rblock, rblockLimit);
                    if (rblock > rblockLimit)
                        block.rowFragment = rblockLimit;
                    else {
                        // For sizeof(T) < maskGranularity, this is a bit of a cheat.
                        //
                        // As long as we do not need to write to this matrix, we can read
                        // in maskGranularity-sized chunks knowing we will never cross a page boundary.

                        if (writable && (T.size() & (maskGranularity - 1)))
                            return false;

                        if (!pseudo
                                && !(isPacked(atype.layout)
                                        && (atype.packSize == rblock)))
                            cblock = 1;

                        vrmask.isFixed = false;
                        vrmask.rsize = rblock;
                        vrmask.bitRep
                                = std::max<int>(T.size() / maskGranularity, 1);
                        vrmask.maskRep = cblock;
                        vrmask.rdivide = std::max<int>(maskGranularity / T, 1);
                    }
                } else {
                    // Fragment it. Could actually handle rowFragment = 2 by changing descriptor.
                    block.rowFragment = 1;
                }
            }

            if (remainderC) {
                if (!colMajor) {
                    // cblock cannot be more than 16 dwords = 64 bytes except for pseudo-block
                    int cblockLimit = pseudo ? cblock : 64 / T;

                    if (avoidFragment)
                        cblock = std::min<int>(cblock, cblockLimit);
                    if (cblock > cblockLimit)
                        block.colFragment = cblockLimit;
                    else {
                        if (writable && (T.size() & (maskGranularity - 1)))
                            return false;

                        if (!pseudo
                                && !(isPacked(atype.layout)
                                        && (atype.packSize == cblock)))
                            rblock = 1;

                        vcmask.isFixed = false;
                        vcmask.rsize = cblock;
                        vcmask.bitRep
                                = std::max<int>(T.size() / maskGranularity, 1);
                        vcmask.maskRep = rblock;
                        vcmask.rdivide = std::max<int>(maskGranularity / T, 1);
                    }
                } else {
                    // Fragment it. Could actually handle colFragment = 2 by changing descriptor.
                    block.colFragment = 1;
                }
            }

            int nbytes = (rblock * cblock) * T;
            block.simdSize
                    = clamp(roundup_pow2(nbytes) / maskGranularity, 1, maxSIMD);
            if (!pseudo) {
                block.count = div_up(nbytes, block.ebytes);
                block.extra = aoword;
                if (block.ebytes == 16 && !(a32 || a64)
                        && !aoword) // BTS/SLM oword loads are oword-addressed.
                    block.addrShift = 4;
            } else {
                block.count = byte ? std::min(nbytes, npack * T) : 1;
                block.ebytes = byte ? 1 : maskGranularity;
                block.extra = 1;
                if (!(a32 || a64 || pseudoblockUseSurface(atype, block)
                            || astrategy.atomic))
                    block.addrShift = log2(block.ebytes);
            }
            block.ld = colMajor ? rblock : cblock;
            break;
        }
    }

    // The mask moduli are always rblock/cblock.
    // Also, clamp mask reps to ensure mask length does not exceed SIMD size.
    if (block.rowMask && !block.rowMask.fixed.isFixed) {
        vrmask.rsize = rblock;
        vrmask.maskRep = std::min<int>(vrmask.maskRep,
                vrmask.rdivide * block.simdSize
                        / (vrmask.bitRep * vrmask.rsize));
        block.noRowsOK = true; // All-zero masks are always OK.
    }
    if (block.colMask && !block.colMask.fixed.isFixed) {
        vcmask.rsize = cblock;
        vcmask.maskRep = std::min<int>(vcmask.maskRep,
                vcmask.rdivide * block.simdSize
                        / (vcmask.bitRep * vcmask.rsize));
        block.noColsOK = true;
    }

    return true;
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::addMasking(RegisterBlock &block,
        bool remainderR, bool remainderC, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {

    block.remainderR |= remainderR;
    block.remainderC |= remainderC;
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::addMasking(vector<RegisterBlock> &layout,
        bool remainderR, bool remainderC, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    for (auto &block : layout)
        addMasking(block, remainderR, remainderC, atype, astrategy);
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getSubblock(Type T, RegisterBlock &blockDst,
        const RegisterBlock &blockSrc, bool column, int x1, int x2,
        int x1Unclamped, int x2Unclamped, bool overrunOK,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    auto effAccessType
            = effectiveAccessType(astrategy.accessType, atype, blockSrc);
    blockDst = blockSrc;

    auto &ns = (column ? blockDst.nc : blockDst.nr);
    auto &nt = (column ? blockDst.nr : blockDst.nc);
    int oldNS = ns;

    (column ? blockDst.offsetC : blockDst.offsetR) += x1;
    ns = x2 - x1;

    if (blockSrc.colMajor == column) {
        if (x1 % blockSrc.crosspack) return false;
        switch (effAccessType) {
            case AccessType::Scattered:
            case AccessType::ChannelScattered:
                blockDst.count = x2 - x1;
                if (blockDst.ebytes == 1)
                    blockDst.count *= T.size();
                else if (T.size() < blockDst.ebytes) {
                    // Extra alignment path with small types.
                    // Check to see if we can still use this element size,
                    //  if not downgrade to scattered byte.
                    // Note for surface accesses this requires shifting the addresses back.
                    auto bcount = blockDst.count * T;
                    if (bcount % 4) {
                        blockDst.ebytes = 1;
                        blockDst.addrShift = 0;
                        blockDst.count = bcount;
                        if (blockDst.count > 4) stub();
                    } else
                        blockDst.count = bcount >> 2;
                }
                break;
            case AccessType::Block:
            case AccessType::PseudoBlock: {
                auto offBytes = x1 * nt * T;
                if (offBytes % blockDst.ebytes) return false;
                auto reqBytes = (x2 - x1) * nt * T;
                auto align
                        = std::min<int>(blockDst.ebytes, blockDst.simdSize * 4);
                if (!overrunOK && (reqBytes & (align - 1))) return false;
                auto ncount = div_up(reqBytes, blockDst.ebytes);
                auto count = roundup_pow2(ncount);
                if (!overrunOK && (count != ncount)) return false;
                if (effAccessType == AccessType::Block)
                    blockDst.count = count;
                else
                    blockDst.simdSize = count / blockDst.count;
                break;
            }
        }

        blockDst.calcBytes(T);
        blockDst.offsetBytes += (x1 * blockSrc.bytes) / oldNS;
    } else {
        blockDst.calcBytes(T);

        switch (effAccessType) {
            case AccessType::Block:
            case AccessType::PseudoBlock: {
                blockDst.offsetBytes += x1 * T * blockSrc.crosspack;

                // Update count and mask information.
                // Beware, cheat: with DW-aligned sub-DW types, true block may be downgraded to byte PseudoBlock,
                //                which requires 2 address registers, though only 1 is used, and only 1 may be allocated.
                int rblock, cblock;
                auto smode
                        = (blockDst.simdSize == maxScatteredSIMD(hw, astrategy))
                        ? ScatterSIMD::Wide
                        : ScatterSIMD::Narrow;
                (void)getBlockInfo(T, atype, astrategy, blockDst.nr,
                        blockDst.nc, blockDst.remainderR, blockDst.remainderC,
                        blockDst.writable, false, smode, 0, 0, rblock, cblock,
                        blockDst);
                blockDst.simplify(T);
                break;
            }
            case AccessType::Scattered:
            case AccessType::ChannelScattered:
                if (T.size() > blockDst.ebytes) return false;
                if (x1 != 0) return false;
                if (!is_zero_or_pow2(x2)) return false;
                blockDst.simdSize = ns * T / blockDst.ebytes;
                break;
        }
    }

    return true;
}

// Get list of subblocks intersecting rows/columns [x1, x2).
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getSubblocks(Type T,
        vector<RegisterBlock> &sublayout, const vector<RegisterBlock> &layout,
        bool column, int x1, int x2, bool overrunOK,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    auto RegisterBlock::*nq = column ? &RegisterBlock::nc : &RegisterBlock::nr;
    auto RegisterBlock::*offsetQ
            = column ? &RegisterBlock::offsetC : &RegisterBlock::offsetR;

    sublayout.clear();

    for (auto &block : layout) {
        int qq1Unclamped = x1 - block.*offsetQ;
        int qq2Unclamped = x2 - block.*offsetQ;
        int qq1 = clamp<int>(qq1Unclamped, 0, block.*nq);
        int qq2 = clamp<int>(qq2Unclamped, 0, block.*nq);
        if (qq2 > qq1) {
            RegisterBlock subblock;
            if (!getSubblock(T, subblock, block, column, qq1, qq2, qq1Unclamped,
                        qq2Unclamped, overrunOK, atype, astrategy)) {
                status << "Could not make subblock." << status_stream::endl;
                return false;
            }
            sublayout.push_back(subblock);
        }
    }
    return true;
}

// Get list of subblocks intersecting rows/columns [x1, x2), and associated address registers and/or indices.
// Returns false if fragmenting failed, or an address register doesn't match a previous one.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getSubblocks(Type T,
        vector<RegisterBlock> &sublayout, vector<GRFRange> *subaddrs,
        vector<int> *indices, const vector<RegisterBlock> &layout,
        const vector<GRFRange> *addrs, bool column, int x1, int x2,
        bool overrunOK, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    auto RegisterBlock::*nq = column ? &RegisterBlock::nc : &RegisterBlock::nr;
    auto RegisterBlock::*offsetQ
            = column ? &RegisterBlock::offsetC : &RegisterBlock::offsetR;

    if (subaddrs) subaddrs->clear();
    if (indices) indices->clear();
    sublayout.clear();

    for (int b = 0; b < int(layout.size()); b++) {
        auto &block = layout[b];
        int qq1Unclamped = x1 - block.*offsetQ;
        int qq2Unclamped = x2 - block.*offsetQ;
        int qq1 = clamp<int>(qq1Unclamped, 0, block.*nq);
        int qq2 = clamp<int>(qq2Unclamped, 0, block.*nq);
        if (qq2 > qq1) {
            RegisterBlock subblock;
            if (!getSubblock(T, subblock, block, column, qq1, qq2, qq1Unclamped,
                        qq2Unclamped, overrunOK, atype, astrategy)) {
                status << "Could not make subblock." << status_stream::endl;
                return false;
            }
            if (subblock.offsetR != block.offsetR
                    || subblock.offsetC != block.offsetC) {
                status << "Subblock is not aligned to parent block."
                       << status_stream::endl;
                return false;
            }
            if (subaddrs) subaddrs->push_back((*addrs)[b]);
            if (indices) indices->push_back(int(b));
            sublayout.push_back(subblock);
        }
    }
    return true;
}

// Get list of subblocks intersecting rows/columns [x1, x2), and associated address registers.
// Returns false if fragmenting failed, or an address register doesn't match a previous one.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getSubblocks(Type T,
        vector<RegisterBlock> &sublayout, vector<GRFRange> &subaddrs,
        const vector<RegisterBlock> &layout, const vector<GRFRange> &addrs,
        bool column, int x1, int x2, bool overrunOK,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    return getSubblocks(T, sublayout, &subaddrs, nullptr, layout, &addrs,
            column, x1, x2, overrunOK, atype, astrategy);
}

// Get list of subblocks intersecting rows/columns [x1, x2), and indices of associated address registers.
// Returns false if fragmenting failed, or an address register doesn't match a previous one.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getSubblocks(Type T,
        vector<RegisterBlock> &sublayout, vector<int> &indices,
        const vector<RegisterBlock> &layout, bool column, int x1, int x2,
        bool overrunOK, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    return getSubblocks(T, sublayout, nullptr, &indices, layout, nullptr,
            column, x1, x2, overrunOK, atype, astrategy);
}

static int getAddr0Offset(const RegisterBlock &block,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    if (atype.base.getModel() == ModelA64) return 0;
    if (effectiveAccessType(astrategy.accessType, atype, block)
            == AccessType::Block)
        return 2;
    return 0;
}

// Get a subregister containing the (shifted) address of the (0,0) entry of a layout.
static Subregister getOriginAddr(const vector<RegisterBlock> &layout,
        const vector<GRFRange> &addrRegs, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, int *shiftOut = nullptr) {
    bool a64 = (atype.base.getModel() == ModelA64);

    for (size_t b = 0; b < layout.size(); b++) {
        const auto &block = layout[b];
        if ((block.offsetR != 0) || (block.offsetC != 0)) continue;

        int off = getAddr0Offset(block, atype, astrategy);

        if (shiftOut) *shiftOut = block.addrShift;
        return addrRegs[b][0].sub(off, a64 ? DataType::uq : DataType::ud);
    }

    if (shiftOut) *shiftOut = 0;
    return Subregister();
}

// Adjust address registers as needed for a newly-created subblock.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::adjustSubblockAddrs(Type T,
        const vector<RegisterBlock> &sublayout,
        const vector<GRFRange> &subaddrs, const vector<RegisterBlock> &layout,
        const vector<GRFRange> &addrs, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, const CommonState &state) {
    bool a64 = (atype.base.getModel() == ModelA64);

    auto nsubs = int(sublayout.size());
    auto nblocks = int(layout.size());

    for (int isub = 0; isub < nsubs; isub++) {
        // Find parent block by comparing address registers.
        auto &subaddr = subaddrs[isub];
        const RegisterBlock *pptr = nullptr;
        for (int i = 0; i < nblocks; i++) {
            if (addrs[i].getBase() == subaddr.getBase()) {
                pptr = &layout[i];
                break;
            }
        }
        if (!pptr) stub();

        auto &block = *pptr;
        auto &subblock = sublayout[isub];

        auto off = getAddr0Offset(block, atype, astrategy);
        auto suboff = getAddr0Offset(subblock, atype, astrategy);

        // Perform any necessary shifts/moves. Moves are only for non-A64 block->pseudoblock settings.
        if (suboff != off) {
            if (subblock.simdSize != 1)
                stub(); // Need to prepare more pseudoblock addresses.
            mov<uint32_t>(1, subaddr[0][suboff], subaddr[0][off]);
        }
        if (subblock.addrShift != block.addrShift) {
            map(hw, a64 ? Type::u64 : Type::u32, subaddr, subaddr, strategy,
                    [&](int simd, GRF r, GRF _) {
                        auto shift = block.addrShift - subblock.addrShift;
                        (shift > 0) ? eshl(simd, r, r, +shift, strategy, state)
                                    : eshr(simd, r, r, -shift, strategy, state);
                    });
        }
    }
}

static inline void postprocessLayout(vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {}

// Count the number of registers needed by a register layout.
static inline int getRegCount(const vector<RegisterBlock> &layout) {
    if (layout.empty()) return 0;

    int lastByte = 0;
    for (auto &l : layout)
        lastByte = std::max(lastByte, l.offsetBytes + l.bytes);

    int log2Bytes = layout[0].log2GRFBytes;
    return (lastByte + (1 << log2Bytes) - 1) >> log2Bytes;
}

// Add a submatrix to a register layout.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::addToRegLayout(Type T,
        std::vector<RegisterBlock> &layout, int nr, int nc, int roff, int coff,
        bool remainderR, bool remainderC, bool writable, bool avoidFragment,
        ScatterSIMD smode, int maxRBlock, int maxCBlock,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    int rblock, cblock;
    RegisterBlock blockTemplate;
    if (!getBlockInfo(T, atype, astrategy, nr, nc, remainderR, remainderC,
                writable, avoidFragment, smode, maxRBlock, maxCBlock, rblock,
                cblock, blockTemplate))
        return false; /* Cannot handle requested block and remainder. */

    if (rblock == 0 || cblock == 0) return false;

    if (isColMajor(atype.layout)) {
        // Order blocks in column-major fashion.
        for (int c = 0; c + cblock <= nc; c += cblock) {
            for (int r = 0; r + rblock <= nr; r += rblock) {
                RegisterBlock thisLayout = blockTemplate;

                thisLayout.nr = rblock;
                thisLayout.nc = cblock;
                thisLayout.offsetR = r + roff;
                thisLayout.offsetC = c + coff;

                layout.push_back(thisLayout);
            }
        }
    } else {
        // Order blocks in row-major fashion.
        for (int r = 0; r + rblock <= nr; r += rblock) {
            for (int c = 0; c + cblock <= nc; c += cblock) {
                RegisterBlock thisLayout = blockTemplate;

                thisLayout.nr = rblock;
                thisLayout.nc = cblock;
                thisLayout.offsetR = r + roff;
                thisLayout.offsetC = c + coff;

                layout.push_back(thisLayout);
            }
        }
    }

    // Handle remainder recursively, checking for infinite recursion.
    int rrem = nr % rblock;
    int crem = nc % cblock;

    status << "Register layout: " << nr << 'x' << nc << " -> blocks " << rblock
           << 'x' << cblock << " remainder " << rrem << 'x' << crem
           << status_stream::endl;

    bool success = true;
    if (rrem || crem) {
        if ((nr == rrem || rrem == 0) && (nc == crem || crem == 0)) {
            status << "Cannot load/store requested matrix block size."
                   << status_stream::endl;
            success = false;
        } else {
            if (rrem)
                success &= addToRegLayout(T, layout, rrem, nc - crem, nr - rrem,
                        0, remainderR, remainderC, writable, avoidFragment,
                        smode, maxRBlock, maxCBlock, atype, astrategy);
            if (crem)
                success &= addToRegLayout(T, layout, nr, crem, 0, nc - crem,
                        remainderR, remainderC, writable, avoidFragment, smode,
                        maxRBlock, maxCBlock, atype, astrategy);
        }
    }
    return success;
}

// Add a submatrix (contiguous in memory) to a block-accessed register layout.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::add1DBlockToRegLayout(Type T,
        vector<RegisterBlock> &layout, int r, int c, bool writable,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    // Skip pseudoblock cases (possible to support though)
    if (needsPseudoblock(hw, T, r, c, atype, astrategy, writable, false))
        return false;

    // Get total number of bytes to load. No masking supported, so stub if
    //  number of bytes not divisible by 16 (1 oword).
    int nbytes = r * c * T;
    int align = 16;

    if (nbytes & (align - 1)) return false;

    // Get block info.
    int maxBBytes = 0;
    int ebytes = 0;
    int extra = 0;
    int addrShift = 0;
    int maxSIMD = 1;

    {
        bool a64 = (atype.base.getModel() == ModelA64);
        bool oword = !a64;
        bool aoword = (atype.base.getModel()
                == ModelSC); // SC only does aligned oword

        extra = aoword;
        ebytes = oword ? 16 : 32;
        maxBBytes = oword ? 128 : 256;
        addrShift = (!a64 && oword && !aoword) ? 4 : 0;
        maxSIMD = 16;
    }

    // Get normalized dimensions.
    bool colMajor = isColMajor(atype.layout);
    int x = colMajor ? r : c;
    auto crosspack = atype.crosspack;

    // Counters for current x and y positions.
    int cx = 0, cy = 0;

    while (nbytes > 0) {
        // Carve out the largest chunk possible.
        int bbytes = std::min<int>(maxBBytes, rounddown_pow2(nbytes));
        int belems = bbytes / T;

        // Create a true load block for first (possibly partial) row/column.
        // Then, create additional no-load blocks for any further (possible partial)
        //   rows/columns until block is exhausted.
        bool first = true;
        while (belems > 0) {
            int nxRem = belems / crosspack;
            int nx = std::min<int>(nxRem, x - cx);
            if (nx <= 0) stub();
            if (cy % crosspack) return false;

            RegisterBlock block;

            block.ld = nx;
            (colMajor ? block.nr : block.nc) = nx;
            (colMajor ? block.nc : block.nr) = crosspack;
            (colMajor ? block.offsetR : block.offsetC) = cx;
            (colMajor ? block.offsetC : block.offsetR) = cy;
            block.colMajor = colMajor;

            if (first) {
                block.ebytes = ebytes;
                block.count = div_up(bbytes, ebytes);
                block.simdSize = std::min(maxSIMD, roundup_pow2(bbytes) >> 2);
            } else
                block.ebytes = block.count = block.simdSize = 0;

            block.extra = extra;
            block.clearFlag();
            block.colMask = MaskInfo::None();
            block.rowMask = MaskInfo::None();
            block.colFragment = 0;
            block.rowFragment = 0;
            block.log2GRFBytes = GRF::log2Bytes(hw);

            block.crosspack = crosspack;
            block.remainderR = false;
            block.remainderC = false;
            block.noRowsOK = false;
            block.noColsOK = false;
            block.descRemR = false;
            block.descRemC = false;
            block.descAssigned = false;
            block.addrShift = addrShift;

            if (first && cx == 0 && (nxRem % x) == 0) {
                // Shortcut: one register block can represent this block access.
                int ny = belems / x;
                (colMajor ? block.nc : block.nr) = ny;
                cy += ny;
                belems = 0;
            } else {
                cx += nx;
                belems -= nx * crosspack;
                if (cx == x) {
                    cy += crosspack;
                    cx = 0;
                }
                first = false;
            }

            layout.push_back(block);
        }

        nbytes -= bbytes;
    }

    return true;
}

static inline int getPartialCrosspack(
        const MatrixAddressing &atype, const RegisterBlock &block) {
    if (block.ebytes == 1)
        return div_up(atype.crosspack, block.colMajor ? block.nc : block.nr);
    else
        return 1;
}

// Get linear element offset in tiled layout (both register and memory)
static int untile(const MatrixAddressing &atype, const RegisterBlock &block,
        int r, int c, int tileR, int tileC, bool reverse = false) {
    bool cm = isColMajor(atype.layout) ^ reverse;

    if (isPacked(atype.layout)) (cm ? r : c) = atype.packSize;

    int cpR = cm ? 1 : atype.crosspack;
    int cpC = cm ? atype.crosspack : 1;

    if (tileR == 0) tileR = r;
    if (tileC == 0) tileC = c;

    int rstride = cm ? tileC : c;
    int cstride = cm ? r : tileR;
    int rtstride = cm ? cpC : tileC;
    int ctstride = cm ? tileR : cpR;

    int i = block.offsetR, j = block.offsetC;
    int iTile = i % tileR;
    int jTile = j % tileC;
    i -= iTile;
    j -= jTile;
    int iCP = iTile % cpR;
    int jCP = jTile % cpC;
    iTile -= iCP;
    jTile -= jCP;
    int idx = i * rstride + j * cstride + iTile * rtstride + jTile * ctstride
            + iCP + jCP;
    return idx;
}

// Re-order a layout so that registers appear in appropriate order
//  (row or column major)
static void sortRegLayout(vector<RegisterBlock> &layout, int r, int c,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, bool reverse = false) {
    auto order = [=](const RegisterBlock &block) {
        return untile(
                atype, block, r, c, astrategy.tileR, astrategy.tileC, reverse);
    };

    std::sort(layout.begin(), layout.end(),
            [&](const RegisterBlock &b1, const RegisterBlock &b2) {
                return (order(b1) < order(b2));
            });
}

// Create a register layout for a matrix.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::getRegLayout(Type T,
        vector<RegisterBlock> &layout, int r, int c, bool remainderR,
        bool remainderC, bool writable, bool avoidFragment, ScatterSIMD smode,
        int maxRBlock, int maxCBlock, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    bool success = false;

    layout.clear();

    // Tiling handling.
    if (astrategy.tileR > 0)
        maxRBlock = (maxRBlock == 0) ? astrategy.tileR
                                     : gcd(int(astrategy.tileR), maxRBlock);
    if (astrategy.tileC > 0)
        maxCBlock = (maxCBlock == 0) ? astrategy.tileC
                                     : gcd(int(astrategy.tileC), maxRBlock);

    // Two separate strategies for creating register layout:
    //    - standard 2D partitioning
    //    - special 1D partitioning for block access to packed inputs.
    if (((atype.layout == MatrixLayout::Pc && atype.packSize == r)
                || (atype.layout == MatrixLayout::Pr && atype.packSize == c))
            && (astrategy.accessType == AccessType::Block) && !remainderR
            && !remainderC && !atype.tileR && !atype.tileC
            && (maxRBlock >= r || maxRBlock == 0)
            && (maxCBlock >= c || maxCBlock == 0)) {
        success = add1DBlockToRegLayout(
                T, layout, r, c, writable, atype, astrategy);
    }
    if (!success) {
        success = addToRegLayout(T, layout, r, c, 0, 0, remainderR, remainderC,
                writable, avoidFragment, smode, maxRBlock, maxCBlock, atype,
                astrategy);
        postprocessLayout(layout, atype, astrategy);
        sortRegLayout(layout, r, c, atype, astrategy);
    }
    if (!success) return false;

    int offsetBytes = 0;
    for (auto &block : layout) {
        if (block.isLoadBlock())
            offsetBytes = alignup_pow2(offsetBytes, GRF::bytes(hw));
        block.calcBytes(T);
        block.offsetBytes = offsetBytes;
        offsetBytes += block.bytes;
        block.simplify(T);
    }

    return true;
}

// Create a register layout for a uniform matrix not backed by memory.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::makeUnbackedRegLayout(Type T,
        vector<RegisterBlock> &layout, int r, int c, bool colMajor,
        int crosspack, int tileR, int tileC) {
    RegisterBlock block {};

    if ((colMajor ? c : r) % crosspack) stub();
    layout.clear();

    if (tileR <= 0) tileR = r;
    if (tileC <= 0) tileC = c;

    int offsetBytes = 0;

    for (int i = 0; i < r; i += tileR) {
        for (int j = 0; j < c; j += tileC) {
            block.log2GRFBytes = GRF::log2Bytes(hw);
            block.nr = std::min(r - i, tileR);
            block.nc = std::min(c - j, tileC);
            block.ld = colMajor ? tileR : tileC;
            block.offsetR = i;
            block.offsetC = j;
            block.colMajor = colMajor;
            block.crosspack = crosspack;
            block.offsetBytes = offsetBytes;

            block.calcBytes(T);
            offsetBytes += block.bytes;

            block.remainderR = false;
            block.remainderC = false;
            block.simdSize = 0; // Not backed by memory.

            layout.push_back(block);
        }
    }
}

// Find the subregister in a layout corresponding to element (r,c), as well as the
//  associated block, and the number of contiguous elements following it (nelems).
// For complex T, returns the subregister containing the real part.
static Subregister findBlockReg(Type T, const vector<RegisterBlock> &layout,
        int r, int c, const GRFMultirange &grfs, int &nelems,
        const RegisterBlock *&block) {
    for (auto &l : layout) {
        const int ne = (1 << l.log2GRFBytes) / T;

        int rr = r - l.offsetR;
        int cc = c - l.offsetC;
        if (rr >= 0 && rr < l.nr && cc >= 0 && cc < l.nc) {
            // It fits! How 'bout that?
            int el;
            if (l.colMajor) {
                int ccx = cc % l.crosspack;
                el = ccx + (rr * l.crosspack) + (cc - ccx) * l.ld;
                nelems = l.nr - rr;
            } else {
                int rrx = rr % l.crosspack;
                el = rrx + (cc * l.crosspack) + (rr - rrx) * l.ld;
                nelems = l.nc - cc;
            }
            el += l.offsetBytes / T;
            int reg = el / ne;
            int subreg = el % ne;
            block = &l;

            return grfs[reg].sub(subreg * T.components(), T.ngen());
        }
    }

    throw std::runtime_error(
            "Could not find requested matrix element in layout.");
}

// Match the register offsets in one register layout to another, reference layout.
// Returns true if successful. If not successful, the layout is unchanged.
static bool matchLayouts(Type T, vector<RegisterBlock> &layout,
        const vector<RegisterBlock> &layoutRef) {
    vector<RegisterBlock> nlayout = layout;

    for (auto &nblock : nlayout) {
        int nelems;
        const RegisterBlock *blockRef;
        auto sr = findBlockReg(T, layoutRef, nblock.offsetR, nblock.offsetC,
                GRFRange(0, 128), nelems, blockRef);

        // Check:
        //  1. Does this register block's offset match the reference block's offset?
        if (sr.getByteOffset()
                != (nblock.offsetBytes & ((1 << nblock.log2GRFBytes) - 1)))
            return false;

        //  2. Is there any free space in the register block?
        if (nblock.nr * nblock.nc * T != nblock.bytes) return false;

        //  3. Does this register block's data layout match the reference block's layout?
        if (blockRef->colMajor != nblock.colMajor) return false;
        if (blockRef->crosspack != nblock.crosspack) return false;

        //  4. Does this register block fit inside the reference block?
        auto RegisterBlock::*nx
                = nblock.colMajor ? &RegisterBlock::nr : &RegisterBlock::nc;
        auto RegisterBlock::*ny
                = nblock.colMajor ? &RegisterBlock::nc : &RegisterBlock::nr;

        if (nblock.*nx < blockRef->*nx) {
            if (nblock.*ny > 1) return false;
        } else if (nblock.*nx == blockRef->*nx) {
            if (nblock.*ny > blockRef->*ny) return false;
        } else
            return false;

        if (nblock.*ny > 1 && (nblock.ld != blockRef->ld)) return false;

        // It's compatible. Point this register block where it belongs.
        nblock.offsetBytes
                = (sr.getBase() << nblock.log2GRFBytes) + sr.getByteOffset();
    }

    std::swap(nlayout, layout);
    return true;
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::setupTeardownLoadStoreDesc(
        bool setup, const CommonStrategy &strategy, CommonState &state) {
    if (strategy.emulate.emulateDWxDW) {
        auto nconstants = 2;
        if (setup)
            for (int s = 0; s < nconstants; s++) {
                state.lsDescConstant[s] = state.ra.alloc_sub<uint32_t>();
                mov(1, state.lsDescConstant[s], uint32_t(0x00100040 << s));
            }
        else
            for (int s = 0; s < nconstants; s++)
                state.ra.safeRelease(state.lsDescConstant[s]);
    }
}

// Output code for loading address register(s) with load/store message descriptors for remainders.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::loadLoadStoreDescriptors(bool load,
        bool store, RegisterBlock &block, const Subregister &count,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    MessageDescriptor descLoad; // a0.0:ud
    MessageDescriptor descStore; // a0.2 (a0.0 if no loads)
    ExtendedMessageDescriptor exdescLoad;
    ExtendedMessageDescriptor exdescStore; // a0.1

    Subregister t1 = state.ra.alloc_sub<uint32_t>();
    Subregister t2 = state.ra.alloc_sub<uint32_t>();

    switch (astrategy.accessType) {
        case AccessType::ChannelScattered: {
            encodeLoadDescriptors(hw, descLoad, exdescLoad, block.simdSize, r0,
                    surface_dword(ChannelMask::rgba), atype.base, null);
            encodeStoreDescriptors(hw, descStore, exdescStore, block.simdSize,
                    surface_dword(ChannelMask::rgba), atype.base, null);
            descLoad.surface.cmask = 0; //
            descStore.surface.cmask = 0; // Fields to fill in.
            exdescStore.parts.extMessageLen = 0; //
            descLoad.parts.responseLen = 0;

            auto bitmask = uint16_t(0x0F00);

            if (strategy.emulate.emulateDWxDW)
                mul(1, t1, state.lsDescConstant[block.simdSize == 16],
                        count.uw());
            else
                mul(1, t1, count,
                        uint32_t(0x00100040) << int(block.simdSize == 16));
            mov(1, t2, bitmask);
            if (store) or_(1, a0.ud(1), t1.uw(0), exdescStore.all);
            shl(1, t2, t2, count);
            and_(1, t1.uw(0), t2, bitmask);
            if (load) or_(1, a0.ud(0), t1, descLoad.all);
            if (store) or_(1, a0.ud(load ? 2 : 0), t1.uw(0), descStore.all);
            break;
        }
        default: hw_unsupported();
    }

    state.ra.safeRelease(t1);
    state.ra.safeRelease(t2);
    block.sfid = exdescLoad.all;
}

template <ngen::HW hw>
InstructionModifier gemm_kernel_generator_t<hw>::getRegisterBlockMask(
        const RegisterBlock &block, CommonState &state) {
    InstructionModifier result;

    if (block.flag) {
        result |= getPhysicalFlag(block.flag, state);
        if (block.flagAll)
            result |= (block.simdSize > 8) ? all16h : all8h;
        else if (block.flagAny)
            result |= (block.simdSize > 8) ? any16h : any8h;
    }

    return result;
}

// Check if a block occupies a contiguous portion of registers in the given GRFMultirange.
// If so, return index of the block's first register in the range.
static inline int contiguityCheck(
        HW hw, const RegisterBlock &block, const GRFMultirange &range) {
    auto offsetBytes = block.offsetBytes;
    if (offsetBytes & (GRF::bytes(hw) - 1))
        if (block.isLoadBlock()) stub();
    auto offsetReg = offsetBytes >> GRF::log2Bytes(hw);
    auto lastReg = GRF::bytesToGRFs(hw, offsetBytes + block.bytes);
    if (!range.contiguous(offsetReg, lastReg - offsetReg)) stub();

    return offsetReg;
}

// Output code for loading a matrix chunk into registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::loadMatrix(const GRFMultirange &dest,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const vector<GRFRange> &addrs, const CommonStrategy &strategy,
        CommonState &state, bool zeroMask) {
    auto nblocks = int(layout.size());

    if (strategy.readSuppressionWA
            && (hasMasking(layout) || !getDefaultNoMask()))
        doReadSuppressionWA(strategy, state);

    for (int l = 0; l < nblocks; l++) {
        auto offsetReg = contiguityCheck(hw, layout[l], dest);
        loadMatrixBlock(dest[offsetReg], layout[l], atype, astrategy, addrs[l],
                strategy, state, zeroMask);
    }
}

// Output code for loading a single matrix block into registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::loadMatrixBlock(const GRF &dest,
        const RegisterBlock &block, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, const GRFRange &addr,
        const CommonStrategy &strategy, CommonState &state, bool zeroMask) {
    InstructionModifier maskMod;

    // Zero SIMD size blocks are filled as part of another load. Skip them.
    if (!block.isLoadBlock()) return;

    // Get mask to apply, if any.
    maskMod |= getRegisterBlockMask(block, state);

    if (block.descAssigned)
        send(block.simdSize | maskMod, static_cast<SharedFunction>(block.sfid),
                dest, addr, null, block.sfid, a0[0]);
    else
        switch (implAccessType(astrategy.accessType, atype, block)) {
            case AccessType::ChannelScattered: {
                static const ChannelMask cmasks[4] = {ChannelMask::r,
                        ChannelMask::rg, ChannelMask::rgb, ChannelMask::rgba};
                if (block.ebytes != 4) stub();
                load(block.simdSize | maskMod, dest,
                        surface_dword(cmasks[block.count - 1]), atype.base,
                        addr);
                break;
            }
            case AccessType::Scattered:
                if (block.ebytes == 8)
                    load(block.simdSize | maskMod, dest,
                            scattered_qword(block.count), atype.base, addr);
                else if (block.ebytes == 4)
                    load(block.simdSize | maskMod, dest,
                            scattered_dword(block.count), atype.base, addr);
                else if (block.ebytes == 1)
                    load(block.simdSize | maskMod, dest,
                            scattered_byte(block.count), atype.base, addr);
                else
                    hw_unsupported();
                break;
            case AccessType::Block:
                if (block.ebytes == 32)
                    load(block.simdSize | maskMod, dest,
                            block_hword(block.count), atype.base, addr);
                else if (block.ebytes == 16 && !block.extra)
                    load(block.simdSize | maskMod, dest,
                            block_oword(block.count), atype.base, addr);
                else if (block.ebytes == 16) {
                    if (block.flag) hw_unsupported();
                    load(block.simdSize, dest, aligned_block_oword(block.count),
                            atype.base, addr);
                } else
                    hw_unsupported();
                if (zeroMask && (atype.base.getModel() == ModelBTS)) {
                    if (block.flag)
                        mov<uint32_t>(block.simdSize | ~maskMod, dest, 0);
                    if (block.simdSize <= 2) mov<uint32_t>(2, dest[2](1), 0);
                    if (block.simdSize <= 1) mov<uint32_t>(1, dest[1], 0);
                }
                break;
            default: stub();
        }
}

// Output code for storing a matrix chunk from registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::storeMatrix(const GRFMultirange &src,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const vector<GRFRange> &addrs, const CommonStrategy &strategy,
        CommonState &state) {
    auto nblocks = int(layout.size());

    for (int l = 0; l < nblocks; l++) {
        auto offsetReg = contiguityCheck(hw, layout[l], src);
        storeMatrixBlock(src[offsetReg], layout[l], atype, astrategy, addrs[l],
                strategy, state);
    }
}

// Output code for storing a matrix block from registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::storeMatrixBlock(const GRF &src,
        const RegisterBlock &block, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, const GRFRange &addr,
        const CommonStrategy &strategy, CommonState &state) {
    InstructionModifier maskMod;

    // Zero SIMD size blocks are filled as part of another store. Skip them.
    if (!block.isLoadBlock()) return;

    // Get mask to apply, if any.
    maskMod |= getRegisterBlockMask(block, state);

    if (block.descAssigned)
        send(block.simdSize | maskMod, static_cast<SharedFunction>(block.sfid),
                null, addr, src, a0.ud(1), a0.ud(0));
    else
        switch (implAccessType(astrategy.accessType, atype, block)) {
            case AccessType::ChannelScattered: {
                static const ChannelMask cmasks[4] = {ChannelMask::r,
                        ChannelMask::rg, ChannelMask::rgb, ChannelMask::rgba};
                if (block.ebytes != 4) stub();
                store(block.simdSize | maskMod,
                        surface_dword(cmasks[block.count - 1]), atype.base,
                        addr, src);
                break;
            }
            case AccessType::Scattered:
                if (block.ebytes == 8)
                    store(block.simdSize | maskMod,
                            scattered_qword(block.count), atype.base, addr,
                            src);
                else if (block.ebytes == 4)
                    store(block.simdSize | maskMod,
                            scattered_dword(block.count), atype.base, addr,
                            src);
                else if (block.ebytes == 1)
                    store(block.simdSize | maskMod, scattered_byte(block.count),
                            atype.base, addr, src);
                else
                    hw_unsupported();
                break;
            case AccessType::Block:
                if (block.ebytes == 32)
                    store(block.simdSize | maskMod, block_hword(block.count),
                            atype.base, addr, src);
                else if (block.ebytes == 16 && !block.extra)
                    store(block.simdSize | maskMod, block_oword(block.count),
                            atype.base, addr, src);
                else
                    hw_unsupported();
                break;
            default: stub();
        }
}

// Atomic addition of a matrix in registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::atomicAddMatrix(Type T,
        const GRFMultirange &src, const vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const vector<GRFRange> &addrs, const CommonProblem &problem,
        const CommonStrategy &strategy, CommonState &state) {
    auto nblocks = int(layout.size());

    if (strategy.readSuppressionWA
            && (hasMasking(layout) || !getDefaultNoMask()))
        doReadSuppressionWA(strategy, state);

    for (int l = 0; l < nblocks; l++) {
        auto offsetReg = contiguityCheck(hw, layout[l], src);
        atomicAddMatrixBlock(T, src[offsetReg], layout[l], atype, astrategy,
                addrs[l], problem, strategy, state);
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::atomicAddMatrixBlock(Type T, const GRF &src,
        const RegisterBlock &block, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy, const GRFRange &addr,
        const CommonProblem &problem, const CommonStrategy &strategy,
        CommonState &state) {
    InstructionModifier maskMod;

    if (!block.isLoadBlock()) return;
    if (block.descAssigned) stub();

    maskMod |= getRegisterBlockMask(block, state);

    // SIMD16 A64 atomics are emulated with 2x SIMD8.
    bool a64 = (atype.base.getModel() == ModelA64);
    int hsize = a64 ? 2 : 1;
    int simd = block.simdSize;
    if (a64) simd = std::min(simd, 8);
    auto nreg = block.nregs();
    auto nregReal = (nreg * simd) / block.simdSize;

    switch (implAccessType(astrategy.accessType, atype, block)) {
        case AccessType::Scattered:
        case AccessType::ChannelScattered:
            if (hasNativeAtomicAdd(hw, T.real(), atype)) {
                auto curSrc = src;
                for (int eoff = 0, hoff = 0; eoff < block.simdSize;
                        eoff += simd, hoff += hsize, curSrc += nregReal) {
                    auto mod = simd | maskMod | ExecutionOffset(eoff);
                    switch (T.real()) {
                        case Type::u64:
                        case Type::s64:
                            atomic(AtomicOp::add, mod, scattered_qword(),
                                    atype.base, addr[hoff], curSrc);
                            break;
                        case Type::u32:
                        case Type::s32:
                            atomic(AtomicOp::add, mod, scattered_dword(),
                                    atype.base, addr[hoff], curSrc);
                            break;
                        case Type::u16:
                        case Type::s16:
                            if (hw < HW::Xe_LP) hw_unsupported();
                            atomic(AtomicOp::add, mod, scattered_word(),
                                    atype.base, addr[hoff], curSrc);
                            break;
                        default: stub();
                    }
                }
            } else {
                // Emulated atomic addition with a compare-and-swap loop.
                auto rOldNew = state.eatomicAddRegs[0];
                auto rSave = state.eatomicAddRegs[1];
                auto rOld = rOldNew[0];
                auto rNew = rOldNew[nregReal];
                auto flagToDo = getPhysicalFlag(state.vflagEAtomicAdd, state);

                if (atype.base.getModel() == ModelA64) {
                    if (block.ebytes == 2)
                        load(block.simdSize | maskMod, rOld, scattered_byte(2),
                                atype.base, addr);
                    else if (block.ebytes == 4)
                        load(block.simdSize | maskMod, rOld, scattered_dword(),
                                atype.base, addr);
                    else if (block.ebytes == 8)
                        load(block.simdSize | maskMod, rOld, scattered_qword(),
                                atype.base, addr);
                } else {
                    if (block.ebytes == 4)
                        load(block.simdSize | maskMod, rOld,
                                surface_dword(ChannelMask::r), atype.base,
                                addr);
                    else
                        stub(); // need to shift addresses
                }
                Label labelMask;

                // Save off high half of data when emulating SIMD16.
                if (block.simdSize > simd)
                    mov<uint32_t>(nregReal * 8, rOld.advance(nreg),
                            rOld.advance(nregReal));

                if (block.flag) {
                    if_(16 | getPhysicalFlag(block.flag, state), labelMask);
                    setDefaultNoMask(false);
                }

                and_(1 | NoMask, flagToDo, ce0,
                        uint16_t((1 << block.simdSize) - 1));

                auto curSrc = src;

                for (int eoff = 0, hoff = 0; eoff < block.simdSize;
                        eoff += simd, hoff += hsize) {
                    auto eoMod = ExecutionOffset(eoff);

                    Label labelCmpXchgLoop;
                    mark(labelCmpXchgLoop);

                    auto dt = T.ngen();
                    add(int(simd * block.ebytes / T.real()) | eoMod | NoMask,
                            rNew.retype(dt), rOld.retype(dt),
                            curSrc.retype(dt));
                    mov<uint32_t>((simd * block.ebytes / 4) | eoMod | NoMask,
                            rSave, rOld);

                    auto atomicMod = simd | flagToDo | eoMod;
                    auto cmpMod = simd | flagToDo | ne | flagToDo | eoMod;

                    switch (block.ebytes) {
                        case 2:
                            if (hw < HW::Xe_LP) hw_unsupported();
                            atomic(AtomicOp::cmpwr, atomicMod, rOld,
                                    scattered_word(), atype.base, addr[hoff],
                                    rOld);
                            break;
                        case 4:
                            atomic(AtomicOp::cmpwr, atomicMod, rOld,
                                    scattered_dword(), atype.base, addr[hoff],
                                    rOld);
                            break;
                        case 8:
                            atomic(AtomicOp::cmpwr, atomicMod, rOld,
                                    scattered_qword(), atype.base, addr[hoff],
                                    rOld);
                            break;
                        default: stub();
                    }

                    if (block.ebytes == 2)
                        cmp<uint16_t>(cmpMod, rSave[0][0](2), rOld[0](2));
                    else if (block.ebytes == 4)
                        cmp<uint32_t>(cmpMod, rSave, rOld);
                    else if (block.ebytes == 8) {
                        if (strategy.emulate.emulate64) {
                            cmp<uint32_t>(simd | ne | flagToDo | eoMod,
                                    rSave[0][0](2), rOld[0](2));
                            cmp<uint32_t>(
                                    simd | ~flagToDo | ne | flagToDo | eoMod,
                                    rSave[0][1](2), rOld[1](2));
                        } else
                            cmp<uint64_t>(cmpMod, rSave, rOld);
                    } else
                        stub();

                    problem.fused ? simtDoWhileLoop(
                            16 | flagToDo | any16h, labelCmpXchgLoop)
                                  : (eoff == 0 && simd == 8)
                                    ? jmpi(1 | flagToDo | any8h,
                                            labelCmpXchgLoop)
                                    : jmpi(1 | flagToDo | any16h,
                                            labelCmpXchgLoop);

                    rOld += 2 * nregReal;
                    rNew += 2 * nregReal;
                    curSrc += nregReal;
                }

                if (block.flag) {
                    mark(labelMask);
                    setDefaultNoMask(true);
                    endif(16);
                }
            }
            break;
        default: hw_unsupported();
    }
}

// Allocate temporary registers for emulating atomic addition.
static inline void allocEAtomicAddRegs(HW hw, Type T,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        CommonState &state, const FlagRegister &flag = FlagRegister()) {
    if (hasNativeAtomicAdd(hw, T.real(), atype)) return;

    int maxNReg = 0;
    for (const auto &block : layout)
        maxNReg = std::max(maxNReg, block.nregs());

    if (maxNReg == 0) return;

    state.eatomicAddRegs[0] = state.ra.alloc_range(maxNReg * 2);
    state.eatomicAddRegs[1] = state.ra.alloc_range(maxNReg);
    state.vflagEAtomicAdd
            = flag.isValid() ? flag : state.raVFlag.allocVirtual();
}

// Free temporary registers for emulating atomic addition.
static inline void freeEAtomicAddRegs(
        CommonState &state, const FlagRegister &flag = FlagRegister()) {
    state.ra.safeRelease(state.eatomicAddRegs[0]);
    state.ra.safeRelease(state.eatomicAddRegs[1]);
    if (flag.isInvalid()) state.raVFlag.release(state.vflagEAtomicAdd);
}

// Release all masks in a mask assignment. If 'start' is specified, only the masks
//  at index 'start' and above will be released.
static inline void releaseMaskAssignments(vector<MaskAssignment> &assignments,
        CommonState &state, int start = 0) {
    for (size_t an = start; an < assignments.size(); an++)
        state.raVFlag.release(assignments[an].flag);

    assignments.resize(start);
    state.wipeActiveVFlags();
}

// Assign mask registers to a register layout.
// The assignments parameter is both input and output:
//     existing assignments will be reused if compatible, and new assignments
//     created as necessary.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::assignMasks(
        std::vector<RegisterBlock> &layout, LoopType rloop, LoopType cloop,
        vector<MaskAssignment> &assignments, CommonState &state) {
    auto nassignOriginal = int(assignments.size());
    bool outOfRegs = false;

    // Loop through layout, collecting masks.
    //  - For each unique mask+loop+offset, allocate an index (flag reg)
    //  - Store new assignment if unique and update flag reg in layout.
    //  - For now, simultaneous row and column masks are not supported.
    for (RegisterBlock &l : layout) {
        MaskAssignment thisAssignment;

        if (l.rowMask) {
            if (l.colMask) stub();

            thisAssignment.mask = l.rowMask;
            thisAssignment.offset = l.offsetR;
            thisAssignment.var = rloop;
        } else if (l.colMask) {
            thisAssignment.mask = l.colMask;
            thisAssignment.offset = l.offsetC;
            thisAssignment.var = cloop;
        } else {
            l.clearFlag();
            continue;
        }

        // Look for compatible mask.
        bool gotMask = false;
        for (auto &a : assignments) {
            if (a.compatible(thisAssignment)) {
                l.flag = a.flag;
                gotMask = true;
                break;
            }
        }

        if (!gotMask) {
            // No compatible mask, so make a new assignment.
            thisAssignment.flag = state.raVFlag.allocVirtual();
            assignments.push_back(thisAssignment);
            if (state.raVFlag.isVirtual(thisAssignment.flag)
                    && state.vflagStorage.isInvalid()) {
                outOfRegs = true;
                break;
            }
            l.flag = thisAssignment.flag;
        }
    }

    if (outOfRegs) {
        // Not enough (virtual) flag registers! Free any masks we added to the list.
        releaseMaskAssignments(assignments, state, nassignOriginal);
        status << "Not enough flag registers available." << status_stream::endl;
        return false;
    }

    return true;
}

// Output code for loading a mask into a flag register.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::loadMask(
        MaskAssignment assignment, Subregister index, CommonState &state) {
    auto flagIdx = assignment.flag;
    RegData flag = getMaskFlag(flagIdx, state);

    if (assignment.mask.fixed.isFixed) {
        // Load fixed mask. Easy.
        mov(1, flag, uint16_t(assignment.mask.fixed.value));
    } else {
        // Load a variable mask, which requires some minor bit-twiddling.
        auto &vmask = assignment.mask.variable;

        uint32_t rsizeScaled = vmask.rsize / vmask.rdivide;
        uint32_t fullMask
                = (1ul << (vmask.bitRep * vmask.maskRep * rsizeScaled)) - 1;
        uint32_t rep1Mask = (1ul << (vmask.bitRep * rsizeScaled)) - 1;
        uint32_t repMultiplier = fullMask / rep1Mask;

        Subregister temp
                = state.ra.alloc_sub(flag.getType(), getHint(HintType::Bank0));
        Subregister mask
                = state.ra.alloc_sub(flag.getType(), getHint(HintType::Bank1));
        Subregister mindex = index;

        if (vmask.rdivide > 1) {
            if (!is_zero_or_pow2(vmask.rdivide)) stub();
            add(1, temp, mindex, vmask.rdivide - 1);
            shr(1, temp, temp, uint16_t(log2(vmask.rdivide)));
            mindex = temp;
        }
        if (vmask.bitRep > 1) {
            mulConstant(1, temp, mindex, vmask.bitRep);
            mindex = temp;
        }
        uint16_t tshift = vmask.bitRep
                * (rsizeScaled + div_up(assignment.offset, vmask.rdivide));
        add(1 | sat, temp, -mindex, tshift);
        if (tshift >= 32)
            min_(1, temp, temp,
                    vmask.bitRep
                            * rsizeScaled); // Ensure shift count doesn't overflow.
        mov(1, mask, rep1Mask);
        if (vmask.maskRep == 1)
            vmask.reverse ? shl(1, flag, mask, temp) : shr(1, flag, mask, temp);
        else {
            vmask.reverse ? stub() // need shl + and
                          : shr(1, mask, mask, temp);
            mul(1, flag, mask, uint16_t(repMultiplier));
        }

        state.ra.safeRelease(temp);
        state.ra.safeRelease(mask);
    }
}

// Output code for loading all masks in a mask assignment to flag registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::loadMasks(
        const vector<MaskAssignment> &assignments, Subregister (&indices)[3],
        CommonState &state, int start) {
    for (size_t an = start; an < assignments.size(); an++) {
        auto &a = assignments[an];
        auto av = static_cast<int>(a.var);
        loadMask(a, indices[av], state);
    }
}

// Ugly helpers handling address shifts. constexpr if would clean this all up.
template <ngen::HW hw>
template <typename BO>
typename std::enable_if<!std::is_base_of<ngen::RegData, BO>::value, BO>::type
gemm_kernel_generator_t<hw>::startShift(
        const BO &ptr, int shift, CommonState &state) {
    return ptr >> shift;
}

template <ngen::HW hw>
Subregister gemm_kernel_generator_t<hw>::startShift(
        const MultishiftSubregister &ptr, int shift, CommonState &state) {
    return ptr >> shift;
}

template <ngen::HW hw>
template <typename BO>
typename std::enable_if<std::is_base_of<ngen::RegData, BO>::value, BO>::type
gemm_kernel_generator_t<hw>::startShift(
        const BO &ptr, int shift, CommonState &state) {
    BO ptrShifted = ptr;

    // Shift pointer as necessary.
    if (shift > 0) {
        ptrShifted = state.ra.alloc_sub(ptr.getType());
        shr(1, ptrShifted, ptr, shift);
    }

    return ptrShifted;
}

template <ngen::HW hw>
template <typename BO>
typename std::enable_if<!std::is_base_of<ngen::RegData, BO>::value>::type
gemm_kernel_generator_t<hw>::doneShift(
        const BO &ptrShifted, int shift, CommonState &state) {}

template <ngen::HW hw>
template <typename BO>
typename std::enable_if<std::is_base_of<ngen::RegData, BO>::value>::type
gemm_kernel_generator_t<hw>::doneShift(
        const BO &ptrShifted, int shift, CommonState &state) {
    if (shift > 0) state.ra.release(ptrShifted);
}

// Output code for setting up address/header GRFs for a single block, given
//  the base pointer (a Subregister, MultishiftSubregister or integer) and leading dimension.
template <ngen::HW hw>
template <typename BO>
void gemm_kernel_generator_t<hw>::setupAddr(const GRFRange &addr, const BO &ptr,
        const RegisterBlock &block, const Subregister &bld, size_t sizeofT,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state,
        const Address2DParams &params) {
    bool shiftBLD = (!bld.isInvalid()
            && (astrategy.accessType == AccessType::Scattered));

    BO ptrShifted = startShift(ptr, block.addrShift, state);
    Subregister bldShifted
            = shiftBLD ? startShift(bld, block.addrShift, state) : bld;

    setupAddrShifted(addr, ptrShifted, block, bldShifted, sizeofT, atype,
            astrategy, strategy, state, params);

    doneShift(ptrShifted, block.addrShift, state);
    if (shiftBLD) doneShift(bldShifted, block.addrShift, state);
}

template <ngen::HW hw>
template <typename BO>
void gemm_kernel_generator_t<hw>::setupAddrShifted(const GRFRange &addr,
        const BO &ptr, const RegisterBlock &block, const Subregister &bld,
        size_t sizeofT, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state,
        const Address2DParams &params) {
    bool a64 = atype.base.getModel() == ModelA64;

    // Nothing to do for non-load blocks.
    if (!block.isLoadBlock()) return;

    auto effAccessType
            = effectiveAccessType(astrategy.accessType, atype, block);
    switch (effAccessType) {
        case AccessType::Scattered:
        case AccessType::ChannelScattered:
        case AccessType::PseudoBlock: {
            int simdSize = block.simdSize;
            bool simd16 = (simdSize > 8);
            auto consecutive = block.extra;
            int s = log2(consecutive);
            int simd = std::min(simdSize, GRF::bytes(hw) >> 2);
            bool simd2x = simdSize > simd;

            // Prepare strided offsets (consecutive offsets for pseudoblock)
            mov(8, addr[0].uw(),
                    Immediate::uv(0 >> s, 1 >> s, 2 >> s, 3 >> s, 4 >> s,
                            5 >> s, 6 >> s, 7 >> s));
            if (simd16)
                mov(8,
                        (simdSize == 16 && simd == 8) ? addr[1].uw(0)(1)
                                                      : addr[0].uw(8)(1),
                        Immediate::uv(8 >> s, 9 >> s, 10 >> s, 11 >> s, 12 >> s,
                                13 >> s, 14 >> s, 15 >> s));

            if (effAccessType != AccessType::PseudoBlock) {
                bool packed = isPacked(atype.layout);

                packed ? mul<uint32_t>(simd, addr[0], addr[0].uw(),
                        uint16_t(atype.packSize * atype.crosspack * sizeofT))
                       : mul<uint32_t>(simd, addr[0], bld, addr[0].uw());
                if (simd2x)
                    packed ? mul<uint32_t>(simd, addr[1], addr[1].uw(),
                            uint16_t(
                                    atype.packSize * atype.crosspack * sizeofT))
                           : mul<uint32_t>(simd, addr[1], bld, addr[1].uw());
            } else {
                auto stride = (block.ebytes * block.count
                                      * getPartialCrosspack(atype, block))
                        >> block.addrShift;
                mulConstant<uint32_t>(simd, addr[0], addr[0].uw(), stride);
                if (simd2x)
                    mulConstant<uint32_t>(simd, addr[1], addr[1].uw(), stride);
            }

            // Add consecutive offsets.
            if ((consecutive > 1)
                    && (effAccessType != AccessType::PseudoBlock)) {
                if ((consecutive - 1) * block.ebytes >= 0x10) stub();
                if (consecutive > 4) stub();
                uint8_t incs[4];
                for (int idx = 0; idx < 4; idx++)
                    incs[idx] = (block.ebytes * (idx % consecutive))
                            >> block.addrShift;
                add<uint32_t>(simdSize, addr, addr,
                        Immediate::uv(incs[0], 0, incs[1], 0, incs[2], 0,
                                incs[3], 0));
            }

            // Add offsets to base.
            if (ptr != 0) {
                if (a64) {
                    {
                        if (simd16)
                            eadd<uint64_t>(8, addr[2], addr[1].ud(), ptr,
                                    strategy, state);
                        eadd<uint64_t>(
                                8, addr[0], addr[0].ud(), ptr, strategy, state);
                    }
                } else
                    add<uint32_t>(simdSize, addr, addr, ptr);
            }
            break;
        }
        case AccessType::Block:
            if (atype.base.getModel() == ModelA64) {
                emov(1, addr[0].uq(0), ptr, strategy);
                // Disable OWord channel mode on SKL.
                if (block.ebytes == 32 && hw < HW::Gen10)
                    mov(1, addr[0].ud(5), uint32_t(0x80000000));
            } else
                mov(1, addr[0].ud(2), ptr); // A32 also has BBA/PTSS...
            break;
    }
}

// Output code for initializing address/header GRFs for an entire register layout.
//  ptr is an integer, Subregister, or MultishiftSubregister holding the base pointer/offset.
template <ngen::HW hw>
template <typename BO>
void gemm_kernel_generator_t<hw>::setupAddr(Type T,
        const vector<GRFRange> &addr, const BO &ptr,
        const vector<RegisterBlock> &layout, const Subregister &ld,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state,
        const Address2DParams &params) {
    auto nblocks = int(layout.size());

    for (int b = 0; b < nblocks; b++) {
        auto &block = layout[b];

        // Skip non-load blocks.
        if (!block.isLoadBlock()) continue;

        auto bparams = params;
        Subregister tempRem;
        // Set up base address.
        setupAddr(addr[b], ptr, block, ld, T.size(), atype, astrategy, strategy,
                state, bparams);
        state.ra.safeRelease(tempRem);

        // Increment as appropriate.
        if (!astrategy.address2D) {
            int offsetFixed = 0, offsetLD = 0, r = 0, c = 0;
            if (isPacked(atype.layout)) getLayoutDims(layout, r, c);
            switch (atype.layout) {
                case MatrixLayout::N:
                    offsetFixed = block.offsetR;
                    offsetLD = block.offsetC;
                    break;
                case MatrixLayout::T:
                    offsetFixed = block.offsetC;
                    offsetLD = block.offsetR;
                    break;
                case MatrixLayout::Pc:
                    offsetFixed = untile(
                            atype, block, r, c, atype.tileR, atype.tileC);
                    break;
                case MatrixLayout::Pr:
                    offsetFixed = untile(
                            atype, block, r, c, atype.tileR, atype.tileC);
                    break;
            }

            offsetFixed *= T.size();

            if (offsetLD == 0) {
                if (offsetFixed != 0)
                    incAddr(addr[b], addr[b], uint16_t(offsetFixed), block,
                            block, atype, astrategy, strategy, state);
            } else {
                Subregister inc = state.ra.alloc_sub<uint32_t>();

                mul(1, inc, ld,
                        uint16_t(
                                offsetLD)); // ld has been converted to bytes already.
                if (offsetFixed != 0) add(1, inc, inc, uint16_t(offsetFixed));
                incAddr(addr[b], addr[b], inc, block, block, atype, astrategy,
                        strategy, state);
                state.ra.safeRelease(inc);
            }
        }
    }
}

// Output code for incrementing the pointers for a given block by a specified # of bytes.
// The amount may be an immediate, Subregister, or MultishiftSubregister.
template <ngen::HW hw>
template <typename I, typename Ir, typename Ic>
void gemm_kernel_generator_t<hw>::incAddr(const GRFRange &addrDst,
        const GRFRange &addrSrc, I inc, Ir incR, Ic incC,
        const RegisterBlock &layoutDst, const RegisterBlock &layoutSrc,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    auto incShifted = startShift(inc, layoutDst.addrShift, state);

    incAddrShifted(addrDst, addrSrc, incShifted, incR, incC, layoutDst,
            layoutSrc, atype, astrategy, strategy, state);

    doneShift(incShifted, layoutDst.addrShift, state);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::incAddr(const GRFRange &addrDst,
        const GRFRange &addrSrc, I inc, const RegisterBlock &layoutDst,
        const RegisterBlock &layoutSrc, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    if (astrategy.address2D) stub();
    incAddr(addrDst, addrSrc, inc, Subregister(), Subregister(), layoutDst,
            layoutSrc, atype, astrategy, strategy, state);
}

template <ngen::HW hw>
template <typename I, typename Ir, typename Ic>
void gemm_kernel_generator_t<hw>::incAddrShifted(const GRFRange &addrDst,
        const GRFRange &addrSrc, I inc, Ir incR, Ic incC,
        const RegisterBlock &layoutDst, const RegisterBlock &layoutSrc,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    // Handle non-load blocks.
    if (!layoutDst.isLoadBlock()) return;
    if (!layoutSrc.isLoadBlock()) stub();

    if (layoutDst.addrShift != layoutSrc.addrShift) stub();

    switch (effectiveAccessType(astrategy.accessType, atype, layoutSrc)) {
        case AccessType::PseudoBlock:
            if (layoutSrc.ebytes != layoutDst.ebytes) stub();
            // fall through
        case AccessType::ChannelScattered:
        case AccessType::Scattered: {
            int naddrDst = layoutDst.simdSize;
            int naddrSrc = layoutSrc.simdSize;
            if (naddrDst > naddrSrc) stub();
            if (atype.base.getModel() == ModelA64) {
                auto simd = 2 * elementsPerGRF(hw, Type::u64);
                for (int ar = 0; naddrDst > 0; ar += 2, naddrDst -= simd)
                    eadd<uint64_t>(std::min(naddrDst, simd), addrDst[ar],
                            addrSrc[ar], inc, strategy, state);
            } else
                add<uint32_t>(naddrDst, addrDst[0], addrSrc[0], inc);
            break;
        }
        case AccessType::Block:
            if (atype.base.getModel() == ModelA64) {
                eadd(1, addrDst[0].uq(0), addrSrc[0].uq(0), inc, strategy,
                        state);
                if (addrDst != addrSrc && layoutDst.ebytes == 32
                        && hw < HW::Gen10 && layoutDst.flag)
                    mov(1, addrDst[0].ud(5),
                            uint32_t(
                                    0x80000000)); // Disable OWord channel mode on SKL.
            } else
                add(1, addrDst[0].ud(2), addrSrc[0].ud(2), inc);
            break;
    }
}

// Output code for incrementing all pointers for a register layout by a specified # of bytes.
// The amount may be an immediate or a subregister.
template <ngen::HW hw>
template <typename I, typename Ir, typename Ic>
void gemm_kernel_generator_t<hw>::incAddr(const vector<GRFRange> &addr, I inc,
        Ir incR, Ic incC, const vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    auto nblocks = int(layout.size());

    for (int b = 0; b < nblocks; b++)
        incAddr(addr[b], addr[b], inc, incR, incC, layout[b], layout[b], atype,
                astrategy, strategy, state);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::incAddr(const vector<GRFRange> &addr, I inc,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    if (astrategy.address2D) stub();
    incAddr(addr, inc, Subregister(), Subregister(), layout, atype, astrategy,
            strategy, state);
}

template <ngen::HW hw>
template <typename I, typename Ir, typename Ic>
void gemm_kernel_generator_t<hw>::incAddrShifted(const vector<GRFRange> &addr,
        I inc, Ir incR, Ic incC, const vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    auto nblocks = int(layout.size());

    for (int b = 0; b < nblocks; b++)
        incAddrShifted(addr[b], addr[b], inc, incR, incC, layout[b], layout[b],
                atype, astrategy, strategy, state);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::incAddrShifted(const vector<GRFRange> &addr,
        I inc, const vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state) {
    if (astrategy.address2D) stub();
    incAddrShifted(addr, inc, Subregister(), Subregister(), layout, atype,
            astrategy, strategy, state);
}

template <typename T>
struct NegativeType {
    typedef T type;
};
template <>
struct NegativeType<uint8_t> {
    typedef int8_t type;
};
template <>
struct NegativeType<uint16_t> {
    typedef int16_t type;
};
template <>
struct NegativeType<uint32_t> {
    typedef int32_t type;
};
template <>
struct NegativeType<int> {
    typedef int32_t type;
};
template <>
struct NegativeType<int64_t> {
    typedef int32_t type;
};

// Output code for incrementing or decrementing all pointers for a register layout by a specified # of bytes.
// The amount may be an immediate or a MultishiftSubregister.
template <ngen::HW hw>
template <typename A, typename I, typename Ir, typename Ic>
void gemm_kernel_generator_t<hw>::incDecAddr(const A &addr, I inc, Ir incR,
        Ic incC, const vector<RegisterBlock> &layout,
        const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state, bool decrement) {
    typename NegativeType<I>::type signedInc = decrement ? -inc : inc;
    typename NegativeType<Ir>::type signedIncR = decrement ? -incR : incR;
    typename NegativeType<Ic>::type signedIncC = decrement ? -incC : incC;

    incAddr(addr, signedInc, signedIncR, signedIncC, layout, atype, astrategy,
            strategy, state);
}

template <ngen::HW hw>
template <typename A, typename I>
void gemm_kernel_generator_t<hw>::incDecAddr(const A &addr, I inc,
        const vector<RegisterBlock> &layout, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy,
        const CommonStrategy &strategy, CommonState &state, bool decrement) {
    if (astrategy.address2D) stub();
    incDecAddr(addr, inc, Subregister(), Subregister(), layout, atype,
            astrategy, strategy, state, decrement);
}

template <HW hw>
void gemm_kernel_generator_t<hw>::setupTeardownRemask(Type T, bool setup,
        int nq, const ngen::Subregister &remQ, const CommonStrategy &strategy,
        CommonState &state) {
    if (setup) {
        auto masks = state.remaskRegs
                = state.ra.alloc_range(div_up(nq * 2, GRF::bytes(hw)));
        int n16 = std::min(nq, elementsPerGRF(hw, Type::u16));
        int ne = elementsPerGRF(hw, T);

        mov<uint16_t>(8, masks[0][0](1), Immediate::uv(0, 1, 2, 3, 4, 5, 6, 7));
        if (nq > 8)
            mov<uint16_t>(8, masks[0][8](1),
                    Immediate::uv(8, 9, 10, 11, 12, 13, 14, 15));
        add<uint16_t>(n16, masks[0], masks[0], -remQ.uw());
        for (int q0 = n16; q0 < nq; q0 += n16)
            add<uint16_t>(n16, masks[q0 / n16], masks[0], -q0);

        switch (T.size()) {
            case 1:
                if (nq >= 256) stub();
                for (int q0 = 0; q0 < nq; q0 += n16)
                    mov(n16, masks[q0 / ne].ub(q0 % ne)(1),
                            masks[q0 / n16].ub(1)(2));
                break;
            case 2:
                map(hw, Type::s16, masks, masks, strategy,
                        [=](int simd, const RegData &r1, const RegData &) {
                            asr(simd, r1, r1, 15);
                        });
                break;
            default: stub();
        }
    } else
        state.ra.safeRelease(state.remaskRegs);
}

template <HW hw>
void gemm_kernel_generator_t<hw>::remaskLayout(Type T, bool column,
        const std::vector<RegisterBlock> &layout, const GRFMultirange &regs,
        const CommonStrategy &strategy, CommonState &state, int offset) {
    if (layout.empty()) return;

    int crosspack = layout[0].crosspack;
    int r, c;
    bool colMajor = isLayoutColMajor(layout);
    getLayoutDims(layout, r, c);

    auto nx = colMajor ? r : c;
    auto ny = colMajor ? c : r;

    for (int y0 = 0; y0 < ny; y0 += crosspack) {
        for (int x0 = 0; x0 < nx;) {
            auto i0 = colMajor ? x0 : y0;
            auto j0 = colMajor ? y0 : x0;
            const RegisterBlock *block;
            int ne;

            auto sub = findBlockReg(T, layout, i0, j0, regs, ne, block);
            if (block->crosspack != crosspack) stub();

            auto necp = ne * crosspack;
            necp = std::min(necp, 2 * elementsPerGRF(hw, T));
            if ((necp * T) & 3) stub();

            int moff = (offset + (column ? j0 : i0)) * T / 4;
            int mreg = moff / elementsPerGRF<uint32_t>(hw);
            int msub = moff % elementsPerGRF<uint32_t>(hw);

            int mstride;
            if (block->colMajor != column && crosspack == 1)
                mstride = 1;
            else if (block->colMajor == column && crosspack == 4 / T)
                mstride = 0;
            else
                stub();

            and_<uint32_t>((necp * T) / 4, sub.ud()(1), sub.ud()(1),
                    state.remaskRegs[mreg][msub](mstride));
            x0 += ne;
        }
    }
}

static bool needsRemask(Type T, bool column, const RegisterBlock &block,
        const MatrixAddressingStrategy &astrategy) {
    if (column ? !block.remainderC : !block.remainderR) return false;

    int maskGranularity = block.ebytes;
    if (block.ebytes >= 16) maskGranularity = 4;
    if (column == block.colMajor) return false;

    return (T.size() < maskGranularity);
}

static bool needsRemask(Type T, bool column,
        const vector<RegisterBlock> &layout,
        const MatrixAddressingStrategy &astrategy) {
    for (auto &block : layout)
        if (needsRemask(T, column, block, astrategy)) return true;
    return false;
}

// Return # of outer products performed at once.
static inline int outerProductCount(
        HW hw, const GEMMProblem &problem, const GEMMStrategy &strategy) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    if (Ta.size() == 1 && Tb.size() == 1 && Tc.size() == 4 && (hw >= HW::Xe_LP))
        return 4;
    return 1;
}

// Get the A and B crosspacks needed by the kernel. 0 indicates any crosspack is OK.
static std::tuple<int, int> targetKernelCrosspack(
        HW hw, const GEMMProblem &problem, const GEMMStrategy &strategy) {
    int opBatch = outerProductCount(hw, problem, strategy);
    bool aColMajor = isColMajor(problem.A.layout)
            ^ isTransposing(strategy.A.accessType);
    bool bColMajor = isColMajor(problem.B.layout)
            ^ isTransposing(strategy.B.accessType);
    bool cColMajor = isColMajor(problem.C.layout)
            ^ isTransposing(strategy.C.accessType);

    if (opBatch == 1) {
        return cColMajor ? std::make_tuple(1, 0) : std::make_tuple(0, 1);
    } else {
        bool bcastOK = cColMajor ? bColMajor : !aColMajor;

        return cColMajor ? std::make_tuple(opBatch, bcastOK ? 1 : opBatch)
                         : std::make_tuple(bcastOK ? 1 : opBatch, opBatch);
    }
}

// Get the A and B crosspacks to use for SLM data.
static std::tuple<int, int> targetSLMCrosspack(
        HW hw, const GEMMProblem &problem, const GEMMStrategy &strategy) {
    int opBatch = outerProductCount(hw, problem, strategy);

    return std::make_tuple(opBatch, opBatch);
}

// Get the A and B tiling needed by the kernel.
static std::tuple<int, int, int, int> targetKernelTiling(
        HW hw, const GEMMProblem &problem, const GEMMStrategy &strategy) {
    return std::make_tuple(0, 0, 0, 0);
}

// Do one outer product (k = 1 slice) of A*B, updating C. ha and hb are the
//  k indices within the A and B chunks, respectively. A_copy, B_copy are the
//  indices of the A, B copies to use.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::outerProduct(int h, int ha, int hb,
        const vector<RegisterBlock> &A_layout,
        const vector<RegisterBlock> &B_layout, const GRFMultirange &A_regs,
        const GRFMultirange &B_regs, GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState &state) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;

    if (isGen9IGEMM(hw, Ta, Tb, Tc)) {
        outerProductGen9IGEMM(ha, hb, A_layout, B_layout, A_regs, B_regs,
                problem, strategy, state);
        return;
    }

    bool mixedMode = ((Tc.real() == Type::f32)
            && (Ta.real() != Type::f32 || Tb.real() != Type::f32));
    bool useDP4A = (Ta.size() == 1 && Tb.size() == 1 && Tc.size() == 4
            && hw >= HW::Xe_LP);

    int opCount = outerProductCount(hw, problem, strategy);
    int aCP, bCP;
    std::tie(aCP, bCP) = targetKernelCrosspack(hw, problem, strategy);

    Subregister Clast;
    int nec = elementsPerGRF(hw, Tc);
    bool globalCM = isLayoutColMajor(state.C_layout);

    bool sortByOffset = (hw < HW::Xe_LP);
    int omax = sortByOffset ? nec : 1;

    struct FMAItem {
        int i, j;
        bool colMajor;
        char component;
        InstructionModifier mod;
        Subregister src0, src1, src2;
    };
    vector<FMAItem> deferred;

    // Emit an FMA instruction.
    auto outputFMA = [&](const InstructionModifier &mod, const Subregister &A,
                             const Subregister &B, const Subregister &C,
                             const RegData &bcastSrc, bool colMajor) {
        if (useDP4A) {
            auto Ar = A.reinterpret(
                    0, isSigned(A.getType()) ? DataType::d : DataType::ud);
            auto Br = B.reinterpret(
                    0, isSigned(B.getType()) ? DataType::d : DataType::ud);

            colMajor ? dp4a(mod, C(1), C(1), Ar(1), Br(0))
                     : dp4a(mod, C(1), C(1), Br(1), Ar(0));
        } else if (C.isARF()) {
            colMajor ? mac(mod, C(1), A(1), bcastSrc)
                     : mac(mod, C(1), bcastSrc, B(1));
        } else {
            // On Xe, always put broadcast in src2 for better bank conflict avoidance.
            colMajor ? mad(mod, C(1), C(1), A(1), bcastSrc)
                     : (hw < HW::Xe_LP) ? mad(mod, C(1), C(1), bcastSrc, B(1))
                                        : mad(mod, C(1), C(1), B(1), bcastSrc);
        }
    };

    // If crosspack nontrivial, do outer product every crosspack iterations.
    if ((h + 1) % opCount) return;
    ha = align_down(ha, opCount);
    hb = align_down(hb, opCount);

    // Loop over offsets.
    for (int o = 0; o < omax; o++) {
        GRFRange broadcastRegs = state.broadcast_regs;
        Subregister lastBcastBase;

        // Decide whether to loop in column or row major order.
        int nx = globalCM ? strategy.unroll[LoopM] : strategy.unroll[LoopN];
        int ny = globalCM ? strategy.unroll[LoopN] : strategy.unroll[LoopM];

        int nxInner = (mixedMode || state.broadcast) ? nx : strategy.fmaSIMD;

        // Last A/B blocks found;
        const RegisterBlock *A_blockLast = nullptr, *B_blockLast = nullptr;

        for (int xo = 0; xo < nx; xo += nxInner) {
            for (int y = 0; y < ny; y++) {
                for (int xi = 0; xi < nxInner && (xi + xo) < nx;) {
                    auto x = xi + xo;
                    auto i = globalCM ? x : y;
                    auto j = globalCM ? y : x;

                    int fmaCount = 1;

                    // Find the appropriate A and B registers. Todo: remainders.
                    // Note returned subregisters always have real types.
                    int na, nb;
                    const RegisterBlock *A_block, *B_block;
                    Subregister A = findBlockReg(
                            Ta, A_layout, i, ha, A_regs, na, A_block);
                    Subregister B = findBlockReg(
                            Tb, B_layout, hb, j, B_regs, nb, B_block);

                    // Check for expected crosspack.
                    if (globalCM ? (aCP && A_block->crosspack != aCP)
                                 : (bCP && B_block->crosspack != bCP))
                        stub();

                    // Check if we should specify {Atomic}.
                    bool atomic
                            = (strategy.atomicFMA && (A_block == A_blockLast)
                                    && (B_block == B_blockLast));
                    A_blockLast = A_block;
                    B_blockLast = B_block;

                    // Do real and imaginary parts of broadcasted matrix element separately.
                    for (int comp = 0; comp < Tc.components(); comp++) {
                        // Find the appropriate C register. Todo: remainders.
                        int nc;
                        const RegisterBlock *C_block;
                        Subregister C = findBlockReg(Tc, state.C_layout, i, j,
                                state.C_regs[comp], nc, C_block);
                        if (C_block->crosspack > 1) stub();

                        // Swap out C register for an accumulator, if necessary.
                        auto C_roff = C.getBase()
                                - state.C_regs[0].ranges[0].getBase();
                        if (C_roff < state.C_accCount)
                            C = AccumulatorRegister(C_roff).sub(
                                    C.getOffset(), Tc.ngen());

                        bool doFMA = true;
                        bool offsetSkip = false;

                        // If sorting by C register offset, check offset.
                        if (sortByOffset && C.getOffset() != o) {
                            doFMA = false;
                            offsetSkip = true;
                        } else {
                            // Check for and avoid bundle conflicts.
                            if (strategy.registerScheme
                                    == GEMMStrategy::CSeparate) {
                                // Pre-Xe standard layout: C never conflicts with A and B.
                                // Just check for conflicts between A and B.
                                if (strategy.duplicateA || strategy.duplicateB)
                                    doFMA = !Bundle::conflicts(hw, A, B);
                            } else if (hw >= HW::Xe_LP) {
                                // Check for conflicts between A/B and C and fix now.
                                if (strategy.duplicateA)
                                    if (Bundle::conflicts(hw, A, C))
                                        A = findBlockReg(Ta, A_layout, i, ha,
                                                state.A1_regs, na, A_block);
                                if (strategy.duplicateB)
                                    if (Bundle::conflicts(hw, B, C))
                                        B = findBlockReg(Tb, B_layout, hb, j,
                                                state.B1_regs, nb, B_block);
                            }
                        }

                        InstructionModifier mod;

                        // Use requested execution size if possible, but limited to available elements.
                        // Decide on kernel type based on register block layouts.
                        bool canColMajor = (A_block->colMajor && globalCM);
                        bool canRowMajor = (!B_block->colMajor && !globalCM);
                        bool colMajor = globalCM;

                        if (!canColMajor && !canRowMajor)
                            fmaCount = 1;
                        else if (canColMajor)
                            fmaCount = rounddown_pow2(
                                    std::min({strategy.fmaSIMD, na, nc}));
                        else
                            fmaCount = rounddown_pow2(
                                    std::min({strategy.fmaSIMD, nb, nc}));

                        int simdSize = fmaCount * Tc.components();

                        // Crosspacked kernels: ensure broadcast matrix is contiguous in k.
                        if (opCount > 1) {
                            bool nativeDir = (globalCM ? B_block->colMajor
                                                       : !A_block->colMajor);
                            auto bcastCrosspack
                                    = (globalCM ? B_block : A_block)->crosspack;
                            if (nativeDir) {
                                if ((globalCM ? nb : na) < opCount) stub();
                                if (bcastCrosspack > 1) stub();
                            } else {
                                if (bcastCrosspack % opCount) stub();
                            }
                        }

                        if (doFMA) {
                            // Add Atomic if appropriate.
                            if (atomic) mod |= Atomic;

                            // Handle broadcast duties.
                            Subregister bcastSrcSub = colMajor ? B : A;
                            bcastSrcSub.setOffset(
                                    bcastSrcSub.getOffset() + comp);
                            RegData bcastSrc = bcastSrcSub;

                            if (state.broadcast) {
                                // Broadcast if necessary: pair of doubles (doubleWA) or single elements.
                                int nbcast = strategy.doubleWA ? 2 : 1;
                                int hs = strategy.doubleWA ? 0 : nbcast;

                                auto bcastType = bcastSrc.getType();
                                Subregister bcastBase = bcastSrcSub;
                                bcastBase.setOffset(
                                        bcastBase.getOffset() & ~(nbcast - 1));

                                if (bcastBase != lastBcastBase) {
                                    auto bcastRegion = bcastBase(
                                            0, nbcast, (nbcast > 1) ? 1 : 0);
                                    {
                                        moveToIntPipe(strategy.fmaSIMD
                                                        * Tc.components(),
                                                bcastRegion);
                                        mov(strategy.fmaSIMD * Tc.components()
                                                        * bcastSrc.getBytes()
                                                        / bcastRegion
                                                                  .getBytes(),
                                                broadcastRegs[0].retype(
                                                        bcastRegion.getType()),
                                                bcastRegion);
                                    }
                                }
                                bcastSrc = broadcastRegs[0].sub(
                                        bcastSrc.getOffset() & (nbcast - 1),
                                        bcastType)(hs);
                                lastBcastBase = bcastBase;
                            }

                            // Finally, perform the long-awaited FMA.
                            outputFMA(simdSize | mod, A, B, C, bcastSrc,
                                    colMajor);
                            Clast = C;
                        } else if (!offsetSkip) {
                            // Save this one for later -- it has conflicts.
                            FMAItem item;

                            item.i = i;
                            item.j = j;
                            item.colMajor = colMajor;
                            item.mod = simdSize | mod;
                            item.src0 = C;
                            item.src1 = A;
                            item.src2 = B;
                            item.component = comp;

                            deferred.push_back(item);
                        }
                    }

                    xi += fmaCount;
                }
            }
        }

        // Handle FMAs deferred due to bank conflicts now.
        for (auto &item : deferred) {
            const RegisterBlock *block;
            int nabc;
            Subregister A = item.src1, B = item.src2, C = item.src0;
            int i = item.i, j = item.j;

            // Resolve said bank conflicts.
            if (strategy.registerScheme == GEMMStrategy::CSeparate) {
                // Don't need to re-check for conflicts in this case -- A and B aren't changed from before
                if (strategy.duplicateA)
                    A = findBlockReg(
                            Ta, A_layout, i, ha, state.A1_regs, nabc, block);
                else if (strategy.duplicateB)
                    B = findBlockReg(
                            Tb, B_layout, hb, j, state.B1_regs, nabc, block);
            }

            // Get broadcast source.
            Subregister bcast = item.colMajor ? B : A;
            bcast.setOffset(bcast.getOffset() + item.component);

            // Issue appropriate FMA.
            outputFMA(item.mod, A, B, C, bcast, item.colMajor);
            Clast = C;
        }

        deferred.clear();
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::outerProductGen9IGEMM(int ha, int hb,
        const vector<RegisterBlock> &A_layout,
        const vector<RegisterBlock> &B_layout, const GRFMultirange &A_regs,
        const GRFMultirange &B_regs, GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState &state) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    DataType tempType
            = (Ta.isSigned() || Tb.isSigned()) ? DataType::w : DataType::uw;

    struct AddItem {
        int simd;
        RegData dest, src0, src1;
    };
    std::vector<AddItem> adds;

    auto replayAdds = [&]() {
        for (auto &item : adds)
            add(item.simd, item.dest, item.src0, item.src1);
        adds.clear();
    };

    bool globalCM = isLayoutColMajor(state.C_layout);

    // Decide whether to loop in column or row major order.
    int nx = globalCM ? strategy.unroll[LoopM] : strategy.unroll[LoopN];
    int ny = globalCM ? strategy.unroll[LoopN] : strategy.unroll[LoopM];

    int tidx = 0;
    for (int y = 0; y < ny; y++) {
        for (int x = 0; x < nx;) {
            auto i = globalCM ? x : y;
            auto j = globalCM ? y : x;

            int fmaCount;

            // Find the appropriate A and B registers.
            int na, nb;
            const RegisterBlock *A_block, *B_block;
            Subregister A
                    = findBlockReg(Ta, A_layout, i, ha, A_regs, na, A_block);
            Subregister B
                    = findBlockReg(Tb, B_layout, hb, j, B_regs, nb, B_block);

            // Find the appropriate C register. Todo: remainders.
            int nc;
            const RegisterBlock *C_block;
            Subregister C = findBlockReg(
                    Tc, state.C_layout, i, j, state.C_regs[0], nc, C_block);

            // No C crosspack support.
            auto cpA = A_block->crosspack, cpB = B_block->crosspack;
            if (C_block->crosspack > 1) stub();

            // Swap out C register for an accumulator, if necessary.
            auto C_roff = C.getBase() - state.C_regs[0].ranges[0].getBase();
            if (C_roff < state.C_accCount)
                C = AccumulatorRegister(C_roff).sub(C.getOffset(), Tc.ngen());

            // Use requested execution size if possible, but limited to available elements.
            // Decide the kernel type based on register block layouts.
            bool canColMajor = (A_block->colMajor && C_block->colMajor);
            bool canRowMajor = (!B_block->colMajor && !C_block->colMajor);
            bool colMajor;

            if (!canColMajor && !canRowMajor) {
                colMajor = true;
                fmaCount = 1;
            } else if (canColMajor) {
                colMajor = true;
                fmaCount = na;
            } else {
                colMajor = false;
                fmaCount = nb;
            }
            fmaCount = rounddown_pow2(std::min(
                    {strategy.fmaSIMD, nb, nc, elementsPerGRF<int16_t>(hw)}));

            auto temp = state.tempMul_regs[tidx++];

            if (C.isARF()) {
                if (colMajor)
                    mac(fmaCount, C(1), A(cpA), B(0));
                else
                    mac(fmaCount, C(1), A(0), B(cpB));
            } else {
                if (colMajor)
                    mul(fmaCount, temp[0].sub(0, tempType)(2), A(cpA), B(0));
                else
                    mul(fmaCount, temp[0].sub(0, tempType)(2), A(0), B(cpB));

                adds.push_back(
                        {fmaCount, C(1), C(1), temp[0].sub(0, tempType)(2)});
            }

            if (tidx >= int(state.tempMul_regs.size())) {
                tidx = 0;
                replayAdds();
            }

            x += fmaCount;
        }
    }

    replayAdds();

    // A4B4 outer product (4 temporary GRFs per 2 C registers) - 2/3 SP
    //
    // mul (32) temp0.0:w<1> A.0:b<32;16,2> B.0:b<32;16,2>   - EM
    // mul (32) temp2.0:w<1> A.1:b<32;16,2> B.1:b<32;16,2>   - FPU
    // add (16) C.0:d<1> C.0:d<8;8,1> temp0.0:w<16;8,2>      - EM
    // add (16) C.0:d<1> C.0:d<8;8,1> temp0.1:w<16;8,2>      - FPU
    // add (16) C.0:d<1> C.0:d<8;8,1> temp2.0:w<16;8,2>      - EM
    // add (16) C.0:d<1> C.0:d<8;8,1> temp2.1:w<16;8,2>      - FPU

    // Faster A4B4 outer product a la non-VNNI (4 temporary GRFs per 2 C registers) - 4/5 SP
    //
    // mul (32) temp0.0:w<1> A.0:b<32;16,2> B.0:b<32;16,2>   - EM
    // mul (32) temp2.0:w<1> A.1:b<32;16,2> B.1:b<32;16,2>   - FPU
    // add (32) (sat) temp0.0:w<1> temp0.0:w<1> temp2.0:w<1> - EM/FPU
    // add (16) C.0:d<1> C.0:d<8;8,1> temp0.0:w<16;8,2>      - EM
    // add (16) C.0:d<1> C.0:d<8;8,1> temp0.1:w<16;8,2>      - FPU
}

// Perform C update operation on C_acc, given original C data in C_load.
// All inputs and outputs are assumed to be of type problem.Ts.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::updateC(const GRFMultirange &C_acc,
        const GRFMultirange &C_accSwap, const GRFMultirange &C_load,
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    auto &alphar = problem.alpha_real;
    auto &betar = problem.beta_real;
    bool alpha1 = (alphar == 1);
    bool alphaM1 = (alphar == -1);
    bool beta1 = (betar == 1);
    bool beta0 = (betar == 0);
    bool betaM1 = (betar == -1);

#define FOR_EACH_C(f) \
    do { \
        map(hw, state.Tacc.real(), C_load, C_acc, strategy, \
                [&](int esize, GRF loaded, GRF acc) { f; }); \
    } while (false)

#define FOR_EACH_C_CX(f) \
    do { \
        map(hw, state.Tacc.real(), C_load, C_acc, C_accSwap, strategy, \
                [&](int esize, GRF loaded, GRF acc, GRF accswap) { f; }); \
    } while (false)

    if (!beta0) {
        if (alpha1 || alphaM1) {
            if (beta1)
                FOR_EACH_C(add(esize, acc, loaded, alpha1 ? acc : -acc));
            else if (betaM1)
                FOR_EACH_C(add(esize, acc, -loaded, alpha1 ? acc : -acc));
            else if (betar.fixed())
                stub(); // beta should be put in a register first.
            else {
                if (!strategy.doubleWA)
                    FOR_EACH_C(mad(esize, acc, alpha1 ? acc : -acc, loaded,
                            betar.getRegAvoiding(hw, loaded)));
                else {
                    FOR_EACH_C(mul(esize, loaded, loaded,
                            betar.getRegAvoiding(hw, loaded)));
                    FOR_EACH_C(add(esize, acc, loaded, alpha1 ? acc : -acc));
                }
            }
        } else {
            bool neg = false;
            if (!beta1) {
                if (betaM1)
                    neg = true;
                else if (!betar.fixed())
                    FOR_EACH_C(mul(esize, loaded, loaded,
                            betar.getRegAvoiding(hw, acc)));
                else
                    stub();
            }
            if (alphar.fixed())
                stub(); // alpha should be put in a register first.
            else {
                if (!strategy.doubleWA)
                    FOR_EACH_C(mad(esize, acc, neg ? -loaded : loaded, acc,
                            alphar.getRegAvoiding(hw, acc)));
                else {
                    FOR_EACH_C(mul(
                            esize, acc, acc, alphar.getRegAvoiding(hw, acc)));
                    FOR_EACH_C(add(esize, acc, neg ? -loaded : loaded, acc));
                }
            }
        }
    } else if (alphaM1)
        FOR_EACH_C(mov(esize, acc, -acc));
    else if (alpha1)
        /* no op */;
    else if (alphar.fixed())
        stub(); // alpha should be put in a register first.
    else {
        FOR_EACH_C(mul(esize, acc, acc, alphar.getRegAvoiding(hw, acc)));
    }

    if (problem.hasPostOp()) {
        Label labelPostOpDone;
        auto flagNonfinal = state.raVFlag.alloc();
        and_(1 | nz | flagNonfinal, null.ud(), state.inputs.flags,
                FlagNonfinalKBlock);
        jmpi(1 | flagNonfinal, labelPostOpDone);
        state.raVFlag.safeRelease(flagNonfinal);
        if (state.Tacc != Type::f32 || !postOpInjector) stub();
        for (const auto &range : C_acc.ranges)
            postOpInjector->compute(range);
        mark(labelPostOpDone);
    }

#undef FOR_EACH_C
#undef FOR_EACH_C_CX
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::reblockLayout(Type Tdst,
        vector<int32_t> &blockMap, vector<RegisterBlock> &layoutDst,
        const vector<RegisterBlock> &layoutRef,
        const vector<RegisterBlock> &layoutSrc, const MatrixAddressing &atype,
        const MatrixAddressingStrategy &astrategy) {
    auto nblockRef = layoutRef.size();
    layoutDst.clear();
    layoutDst.reserve(nblockRef);
    blockMap.clear();
    blockMap.reserve(nblockRef + 1);
    blockMap.push_back(0);
    for (auto &blockRef : layoutRef) {
        RegisterBlock blockDst, blockMid;
        for (auto &blockSrc : layoutSrc) {
            int rr1 = blockRef.offsetR - blockSrc.offsetR,
                rr2 = rr1 + blockRef.nr;
            int cc1 = blockRef.offsetC - blockSrc.offsetC,
                cc2 = cc1 + blockRef.nc;
            if (rr1 >= blockRef.nr || rr2 <= 0) continue;
            if (cc1 >= blockRef.nc || cc2 <= 0) continue;
            if (!getSubblock(Tdst, blockMid, blockSrc, false, rr1, rr2, rr1,
                        rr2, true, atype, astrategy))
                return false;
            if (!getSubblock(Tdst, blockDst, blockMid, true, cc1, cc2, cc1, cc2,
                        true, atype, astrategy))
                return false;
            layoutDst.push_back(blockDst);
        }
        blockMap.push_back(int32_t(layoutDst.size()));
    }
    return true;
}

// Update an entire C layout.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::updateCLayout(
        const vector<RegisterBlock> &layoutExt, const GRFRange (&C_addr0)[2],
        COperation op, GEMMProblem &problem, GEMMStrategy &strategy,
        GEMMState &state) {
#define FOR_EACH_C for (int q = 0; q < C_count; q++)
    auto Tc = problem.Tc, Tc_ext = problem.Tc_ext, Ts = problem.Ts;
    bool loadOnly = (op == COperation::Load);
    bool beta0 = problem.beta0();
    bool needLoad = (!beta0 && !loadOnly);
    bool copyC = state.copyC;
    int C_count = (op == COperation::UpdateStore) ? state.C_count : 1;
    bool cColMajor = isColMajor(problem.C.layout);

    auto nblocks = int(layoutExt.size());
    bool haveDescs = layoutExt[0].descAssigned;
    const auto &C_block0 = state.C_layoutExt[0];

    vector<GRFRange>(&C_addrs)[2] = state.C_addrs;
    GRFMultirange C_extRange, C_copyRange;
    GRFMultirange &C_accRange = state.C_regs[0];
    auto &C_extRegs = C_extRange.ranges;
    auto &C_copyRegs = C_copyRange.ranges;
    vector<GRFRange> C_convertRegs;

    Subregister tempStorage = state.ra.alloc_sub<uint64_t>();
    Subregister temp[2] = {tempStorage.ud(0), tempStorage.ud(1)};

    for (int q = 0; q < C_count; q++)
        C_addrs[0].clear();

    // Map layout to blocks in internal C layout as needed.
    vector<RegisterBlock> layout;
    vector<int> blockMap;
    if (copyC) {
        if (!reblockLayout(Tc, blockMap, layout, layoutExt, state.C_layout,
                    problem.C, strategy.C))
            stub();
    } else {
        layout = layoutExt;
        blockMap.resize(nblocks + 1);
        for (int i = 0; i <= nblocks; i++)
            blockMap[i] = i;
    }

    // Prepare for late C conversion.
    bool lateCConvert = (!loadOnly && !strategy.C.atomic
            && problem.needsTsConvert() && state.Tacc != Ts);
    bool copyCLoad = needLoad && (copyC || lateCConvert);
    if (lateCConvert && Tc.isComplex()) stub();

    // Load as much of C as is possible at a time, given register space.
    for (int lstart = 0; lstart < nblocks;) {
        int lend;

        // Allocate address and data registers for C updating. If allocator chokes,
        //  proceed with the registers we were able to allocate.
        //
        // At the same time, build up three layouts for this chunk of C:
        //   sublayoutExt:   C data to be loaded/stored
        //   sublayoutCopy:  copied C data
        //   sublayoutAcc:   C data in accumulators
        bool allocOK = true;
        auto tryAlloc = [&](int regs, Bundle hint = Bundle()) {
            auto range = state.ra.try_alloc_range(regs, hint);
            allocOK &= range.isValid();
            return range;
        };

        vector<RegisterBlock> sublayoutExt, sublayoutCopy, sublayoutAcc;
        int bytes = 0, bytesConvert = 0;
        for (lend = lstart; lend < nblocks; lend++) {
            auto blockExt = layoutExt[lend];
            auto naddr = addrGRFCount(problem.C, strategy.C, blockExt);
            FOR_EACH_C C_addrs[q].push_back(
                    (blockExt.offsetR == 0 && blockExt.offsetC == 0)
                            ? C_addr0[q]
                            : tryAlloc(naddr));
            int expand
                    = lateCConvert ? div_up(Ts.size(), state.Tacc.size()) : 1;
            if (needLoad || copyC)
                C_extRegs.push_back(tryAlloc(
                        blockExt.nregs(), getHint(HintType::CLoad, strategy)));
            if (copyCLoad)
                for (int l = blockMap[lend]; l < blockMap[lend + 1]; l++)
                    C_copyRegs.push_back(tryAlloc(layout[l].nregs() * expand,
                            getHint(HintType::CLoad, strategy)));
            if (lateCConvert)
                for (int l = blockMap[lend]; l < blockMap[lend + 1]; l++)
                    C_convertRegs.push_back(
                            tryAlloc(layout[l].nregs() * expand));
            if (!allocOK) break;

            blockExt.offsetBytes = bytes;
            bytes += blockExt.nregs() * GRF::bytes(hw);
            sublayoutExt.push_back(blockExt);

            if (copyCLoad)
                for (int l = blockMap[lend]; l < blockMap[lend + 1]; l++) {
                    auto block = layout[l];
                    block.offsetBytes = bytesConvert;
                    bytesConvert += block.nregs() * expand * GRF::bytes(hw);
                    sublayoutCopy.push_back(block);
                }
        }

        int listart = blockMap[lstart];
        int liend = blockMap[lend];

        sublayoutAcc.reserve(liend - listart);
        for (int l = listart; l < liend; l++)
            sublayoutAcc.push_back(layout[l]);

        // Set up C addresses. Block 0's address is already done.
        for (int l = lstart; l < lend; l++) {
            auto &block = sublayoutExt[l - lstart];
            if (strategy.C.address2D)
                FOR_EACH_C incAddr(C_addrs[q][l - lstart], C_addr0[q],
                        Subregister(), block.offsetR, block.offsetC, block,
                        C_block0, problem.C, strategy.C, strategy, state);
            else if (!(block.offsetR == 0 && block.offsetC == 0)) {
                auto offsetFixed = cColMajor ? block.offsetR : block.offsetC;
                auto offsetLD = cColMajor ? block.offsetC : block.offsetR;

                if (offsetLD != 0) {
                    FOR_EACH_C mulConstant(
                            1, temp[q], state.inputs.ldc[q], offsetLD);
                    if (offsetFixed != 0)
                        add(C_count, temp[0](1), temp[0](1),
                                uint16_t(offsetFixed * Tc_ext));
                    FOR_EACH_C incAddr(C_addrs[q][l - lstart], C_addr0[q],
                            temp[q], block, C_block0, problem.C, strategy.C,
                            strategy, state);
                } else {
                    uint16_t inc = offsetFixed * Tc_ext;
                    FOR_EACH_C incAddr(C_addrs[q][l - lstart], C_addr0[q], inc,
                            block, C_block0, problem.C, strategy.C, strategy,
                            state);
                }
            }
        }

        if (strategy.C.atomic) {
            // Atomic update.
            // Alpha scaling is done earlier; beta scaling isn't supported.
            if (!problem.alpha1() || !problem.beta1()) stub();
            if (copyC)
                if (!copyRegisters(state.Tacc, Tc_ext, sublayoutAcc,
                            sublayoutExt, C_accRange, C_extRange, 0, 0, false,
                            strategy, state))
                    stub();

            auto &sublayoutSrc = copyC ? sublayoutExt : sublayoutAcc;
            auto &C_srcRange = copyC ? C_extRange : C_accRange;
            FOR_EACH_C atomicAddMatrix(Tc_ext, C_srcRange, sublayoutSrc,
                    problem.C, strategy.C, C_addrs[q], problem, strategy,
                    state);
        } else {
            // Regular update.
            auto Tload = Tc_ext;
            if (!beta0 || loadOnly) {
                // Set up a0.0 descriptor for loads if needed.
                if (lstart > 0 && haveDescs) mov(1, a0.ud(0), a0.ud(3));

                // Load C data.
                auto &sublayoutLoad
                        = (loadOnly && !copyC) ? sublayoutAcc : sublayoutExt;
                auto &C_loadRange
                        = (loadOnly && !copyC) ? C_accRange : C_extRange;
                loadMatrix(C_loadRange, sublayoutLoad, problem.C, strategy.C,
                        C_addrs[0], strategy, state);

                // Set up a0.0 descriptor for stores (and save load descriptors) if needed.
                if (haveDescs && !loadOnly) {
                    if (lend < nblocks) mov(1, a0.ud(3), a0.ud(0));
                    mov(1, a0.ud(0), a0.ud(2));
                }

                // Copy loaded data as needed.
                if (copyCLoad) {
                    auto &sublayoutDst
                            = loadOnly ? sublayoutAcc : sublayoutCopy;
                    auto &C_dstRange = loadOnly ? C_accRange : C_copyRange;
                    Tload = lateCConvert ? Ts : Tc;
                    if (!copyRegisters(Tc_ext, Tload, sublayoutExt,
                                sublayoutDst, C_extRange, C_dstRange, 0, 0,
                                false, strategy, state))
                        stub();
                }
            }

            // Late C conversion.
            auto originalTacc = state.Tacc;
            if (lateCConvert) {
                for (int li = listart; li < liend; li++) {
                    GRFRange C_acc {state.C_regs[0][layout[li].offsetReg()],
                            layout[li].nregs()};
                    copyRegisterBlock(state.Tacc, Ts, layout[li], layout[li],
                            C_acc, C_convertRegs[li - listart], 0, 0, strategy,
                            state);
                }
                state.Tacc = Ts;
            }

            // Alpha/beta scaling and optional fp32<->int32 conversion.
            if (!loadOnly)
                for (int phase = 0; phase < 3; phase++) {
                    for (int li = listart; li < liend; li++) {
                        GRFRange C_acc0 {
                                state.C_regs[0][layout[li].offsetReg()],
                                layout[li].nregs()};
                        GRFRange C_acc = lateCConvert
                                ? C_convertRegs[li - listart]
                                : C_acc0;
                        GRFRange C_accSwap;
                        GRFRange C_load = beta0
                                ? C_acc
                                : copyCLoad ? C_copyRegs[li - listart]
                                            : C_extRegs[li - listart];
                        switch (phase) {
                            case 0:
                                if (!beta0)
                                    convert(C_load, Tload, state.Tacc, problem,
                                            strategy, state);
                                break;
                            case 1:
                                updateC(C_acc, C_accSwap, C_load, problem,
                                        strategy, state);
                                break;
                            case 2:
                                if (lateCConvert)
                                    copyRegisterBlock(state.Tacc, Tc,
                                            layout[li], layout[li], C_acc,
                                            C_acc0, 0, 0, strategy, state);
                                else
                                    convert(C_acc, state.Tacc, Tc, problem,
                                            strategy, state);
                                break;
                        }
                    }
                }

            state.Tacc = Tc;

            // Store updated data.
            if (op == COperation::UpdateStore) {
                if (copyC)
                    if (!copyRegisters(state.Tacc, Tc_ext, sublayoutAcc,
                                sublayoutExt, C_accRange, C_extRange, 0, 0,
                                false, strategy, state))
                        stub();

                auto &sublayoutSrc = copyC ? sublayoutExt : sublayoutAcc;
                auto &C_srcRange = copyC ? C_extRange : C_accRange;
                FOR_EACH_C storeMatrix(C_srcRange, sublayoutSrc, problem.C,
                        strategy.C, C_addrs[q], strategy, state);
            }

            state.Tacc = originalTacc;
        }

        // Free address and data registers, including C accumulators that are no longer used...
        //  ... except C_addr0. I need that!
        FOR_EACH_C safeReleaseRanges(C_addrs[q], state);
        safeReleaseRanges(C_extRange, state);
        safeReleaseRanges(C_copyRange, state);
        safeReleaseRanges(C_convertRegs, state);
        if (op == COperation::UpdateStore)
            for (int li = listart; li < liend; li++) {
                GRFRange C_acc {state.C_regs[0][layout[li].offsetReg()],
                        layout[li].nregs()};
                state.ra.safeRelease(C_acc);
            }
        FOR_EACH_C state.ra.claim(C_addr0[q]);

        // Check for forward progress.
        if (lend == lstart) throw out_of_registers_exception();
        lstart = lend;
    }

    // Release temporaries.
    state.ra.safeRelease(tempStorage);

    // Re-claim all the C registers we freed, so as not to disturb the caller's RegisterAllocator.
    reclaimRanges(state.C_regs[0], state);
#undef FOR_EACH_C
}

// Assign runtime-computed descriptor information to all blocks in this layout.
// Returns true if successful; false if not all blocks in layout are compatible.
static inline bool assignAllDescs(vector<RegisterBlock> &layout) {
    for (auto &block : layout) {
        if (block.simdSize != layout[0].simdSize) return false;
        block.descAssigned = true;
        block.sfid = layout[0].sfid;
    }

    return true;
}

// Output code for standard C remainder handling.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::doStdCRemainder(
        vector<RegisterBlock> &layoutExt, bool inside, bool columns[2],
        StdCRemType remTypes[2], bool fragments[2], bool fragPositives[2],
        int fragSizes[2], const GRFRange (&C_addr0)[2], COperation op,
        vector<MaskAssignment> &masks, GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState state) {
    auto Tc_ext = problem.Tc_ext;
    auto column = columns[inside];
    LoopType loop = column ? LoopN : LoopM;
    auto remType = remTypes[loop];
    auto fragment = fragments[loop];
    auto fragPositive = fragPositives[loop];
    auto fragSize = fragSizes[loop];
    auto unroll = strategy.unroll[loop];
    auto remainder = state.remainders[loop];

    bool canEOT = !state.isNested && (op == COperation::UpdateStore);

    Label lEnd;

    // The "q" dimension is the one whose remainder we are currently handling.
    auto RegisterBlock::*nq = column ? &RegisterBlock::nc : &RegisterBlock::nr;
    auto RegisterBlock::*offsetQ
            = column ? &RegisterBlock::offsetC : &RegisterBlock::offsetR;

    // Status message.
    status << "C remainder handling (" << char('m' + column) << ") " << remType;
    if (fragment) status << ", fragment";
    if (fragPositive) status << ", no empty accesses";
    status << status_stream::endl;

    // Allocate temporaries for emulated atomic addition if needed.
    if (!inside && strategy.C.atomic)
        allocEAtomicAddRegs(hw, Tc_ext, layoutExt, problem.C, state);

    // Handle a subproblem. Return true if successful.
    auto descend = [&](vector<RegisterBlock> &sublayoutExt,
                           bool full = false) -> bool {
        bool success = true;
        auto nMasksOriginal = int(masks.size());

        if (remType == StdCRemType::Mask) {
            if (!full) {
                // Assign and load any extra masks needed.
                if (!assignMasks(sublayoutExt, LoopM, LoopN, masks, state))
                    return false;
                loadMasks(masks, state.remainders, state, nMasksOriginal);
            } else {
                // Clear out mask assignments in this dimension.
                for (auto &block : layoutExt)
                    block.clearFlag();
            }
        }

        // Recursively handle subproblem.
        if (inside)
            updateCLayout(sublayoutExt, C_addr0, op, problem, strategy, state);
        else
            success = doStdCRemainder(sublayoutExt, true, columns, remTypes,
                    fragments, fragPositives, fragSizes, C_addr0, op, masks,
                    problem, strategy, state);

        // Free any new masks.
        if (remType == StdCRemType::Mask)
            releaseMaskAssignments(masks, state, nMasksOriginal);
        return success;
    };

    // Exit remainder handling.
    auto done = [&]() {
        if (!canEOT)
            jmpi(1, lEnd);
        else
            epilogue(strategy, state);
    };

    // Main code.
    bool success = false;
    pushStream();

    if (!fragment) {
        // If descriptor-based remainders requested, all blocks should be smaller than fragSize.
        // Load descriptors based on total remainder in this (rare) case.
        if (remType == StdCRemType::Descriptor) {
            loadLoadStoreDescriptors(!problem.beta0(), true, layoutExt[0],
                    remainder, problem.C, strategy.C, strategy, state);
            if (!assignAllDescs(layoutExt)) goto failed;
        }
        // Nothing else to do: go down a level.
        if (!descend(layoutExt)) goto failed;
    } else {
        // Use SIMT control flow if remainders could be different between fused threads or if jump tables disabled.
        const bool useSIMTFlow = strategy.noJumpTables
                || (problem.fused
                        && (problem.fusedLoop == loop
                                || problem.fusedLoop == LoopAny));

        // Fix up fragment size (fragSize).
        //  - Check that every block starts at a multiple of fragSize; if not fall back on fragSize 1.
        //  - Max fragment size is 16.
        fragSize = std::min<int>(fragSize, 16);
        for (auto &block : layoutExt) {
            if (block.*offsetQ % fragSize) {
                fragSize = 1;
                break;
            }
        }

        // There are two strategies for fragmenting for remainder handling:
        //    fragSize = 1:  Try to get the largest blocks as possible. These are always fragPositive.
        //    fragSize > 1:  Always use blocks of size fragSize in the q dimension.
        if (fragSize == 1) {
            if (!useSIMTFlow) {
                // SIMD control flow, using a jump table.
                Subregister temp = state.ra.alloc_sub<uint32_t>();
                vector<Label> rlabels(unroll);

                // Generate jump table.
                shl(1, temp, remainder,
                        uint16_t(4)); // Multiply by instruction length.
                if (isXe) // Xe+ jmpi is relative to current IP.
                    add(1, temp, temp, uint16_t(16));
                jmpi(1, temp.d()); // Indexed jump into jump table.
                for (int r = 0; r < unroll; r++)
                    jmpi(1, rlabels[r]);

                // Full remainder case: continue downward.
                status << "Code for full " << char('m' + column) << " remainder"
                       << status_stream::endl;
                if (!descend(layoutExt, true)) goto failed;
                inside ? jmpi(1, rlabels[0]) : done();

                // Remainder handling.
                vector<bool> qdone(unroll, false);
                qdone[0] = true;
                int qnext = 0;
                for (int nqtodo = unroll - 2; nqtodo >= 0; nqtodo--) {
                    // Decide which q to do.
                    int q;
                    if (qnext > 0)
                        q = qnext;
                    else {
                        for (q = unroll - 1; q >= 0; q--)
                            if (!qdone[q]) break;
                    }

                    status << "Code for " << char('m' + column) << " remainder "
                           << q << status_stream::endl;

                    mark(rlabels[q]);

                    // Figure out how many rows/columns to take.
                    int chunkSize = q & ~(q - 1); // = 1 << lowest set bit

                    // Look through all blocks in this row/column, and reduce chunk size if appropriate.
                    for (auto &block : layoutExt) {
                        if (!block.isLoadBlock())
                            stub(); // Dummy blocks should be replaced by real ones...
                        int qq = q
                                - block.*offsetQ; // Note q = 1 + last row/column.
                        if (qq > 0 && qq <= block.*nq)
                            chunkSize = std::min<int>(chunkSize, qq);
                    }

                    // With chunk size chosen, get rows/columns [q - chunkSize, q) of intersecting blocks.
                    vector<RegisterBlock> C_subblocksExt;
                    if (!getSubblocks(Tc_ext, C_subblocksExt, layoutExt, column,
                                q - chunkSize, q, false, problem.C, strategy.C))
                        goto failed;

                    // Perform the requested update.
                    if (!descend(C_subblocksExt)) goto failed;

                    // Go to next remainder handler, or return.
                    qdone[q] = true;
                    qnext = q - chunkSize;
                    if (nqtodo > 0) {
                        if (qnext == 0 && canEOT)
                            epilogue(strategy, state);
                        else if (qdone[qnext]) {
                            jmpi(1, rlabels[qnext]);
                            qnext = 0;
                        }
                    }
                }
                mark(rlabels[0]);

                state.ra.safeRelease(temp);
            } else {
                // SIMT control flow: massively nested if-else.

                // Handle remainder in the range [q0, q1).
                std::function<bool(int, int)> handleRemainder
                        = [&](int q0, int q1) -> bool {
                    Label labelElse, labelEndif;

                    int qChunk = rounddown_pow2(q1 - q0 - 1);

                    if (qChunk == 0) qChunk = 1;

                    status << "Code for " << char('m' + column)
                           << " remainders " << q0 << " - " << (q1 - 1)
                           << status_stream::endl;

                    if (q1 - q0 > 1) {
                        cmp(16 | ge | state.flagAP, remainder,
                                uint16_t(q0 + qChunk));
                        if_(16 | state.flagAP,
                                (qChunk > 1) ? labelElse : labelEndif,
                                labelEndif);
                    }

                    vector<RegisterBlock> C_subblocksExt;
                    if (!getSubblocks(Tc_ext, C_subblocksExt, layoutExt, column,
                                q0, q0 + qChunk, false, problem.C, strategy.C))
                        return false;

                    if (!descend(C_subblocksExt)) return false;

                    if (q1 - q0 > 1) {
                        if (qChunk > 1) {
                            if (!handleRemainder(q0 + qChunk, q1)) return false;

                            else_(16, labelEndif);
                            mark(labelElse);

                            if (!handleRemainder(q0, q0 + qChunk)) return false;
                        }

                        mark(labelEndif);
                        endif(16);
                    }

                    return true;
                };

                Label labelRem, labelRemDone, labelDone;

                cmp(16 | ge | state.flagAP, remainder, uint16_t(unroll));
                if_(16 | state.flagAP, labelRem, labelDone);

                status << "Code for " << char('m' + column) << " full remainder"
                       << status_stream::endl;
                if (!descend(layoutExt, true)) goto failed;

                else_(16, labelDone);
                mark(labelRem);

                if (!handleRemainder(0, unroll)) goto failed;

                mark(labelDone);
                endif(16);
                setDefaultNoMask(true);
            }
        } else {
            auto handleRemainderFP = [&](int q0, int q1) -> bool {
                // Get rows/columns [q0, q1) of intersecting blocks.
                vector<RegisterBlock> C_subblocksExt;
                if (!getSubblocks(Tc_ext, C_subblocksExt, layoutExt, column, q0,
                            q1, false, problem.C, strategy.C))
                    return false;

                if (remType == StdCRemType::Descriptor) {
                    // Load address registers for subsequent loads and stores.
                    Subregister rcount = state.ra.alloc_sub<uint32_t>();
                    Subregister mremainder = remainder;

                    if (q0 != 0) {
                        add(1 | sat, rcount, mremainder, int16_t(-q0));
                        mremainder = rcount;
                    }
                    if (q1 < unroll) {
                        min_(1, rcount, mremainder, uint16_t(fragSize));
                        mremainder = rcount;
                    }

                    loadLoadStoreDescriptors(!problem.beta0(), true,
                            C_subblocksExt[0], mremainder, problem.C,
                            strategy.C, strategy, state);
                    if (!assignAllDescs(C_subblocksExt)) return false;

                    state.ra.safeRelease(rcount);
                }

                // Perform the requested update.
                return descend(C_subblocksExt);
            };

            if (!useSIMTFlow) {
                // SIMD control flow, possibly using a jump table.
                int N = div_up(unroll, fragSize);
                vector<Label> rlabels(N); // Targets for jump table.
                Label rdone;

                // Create a jump table, if needed.
                if (fragPositive) {
                    Subregister t1 = state.ra.alloc_sub<uint32_t>();
                    Subregister t2 = state.ra.alloc_sub<uint32_t>();

                    add(1 | sat, t2, remainder, int16_t(-unroll + 1));
                    add(1, t1, remainder, int16_t(-1 + (isXe ? fragSize : 0)));
                    add(1, t1, t1,
                            t2); // Increment index if remainder == unroll.
                    if (fragSize < 16) // Precondition: fragSize <= 16.
                        mulConstant(1, t1, t1,
                                16 / fragSize); // Multiply by instruction length (16b/uncompacted instruction)
                    and_(1, t1, t1,
                            uint16_t(0xFFF0)); // Mask off unwanted bits.
                    jmpi(1, t1.d()); // Indexed jump into jump table.
                    for (int r = 0; r < N; r++)
                        jmpi(1, rlabels[r]);

                    state.ra.safeRelease(t2);
                    state.ra.safeRelease(t1);
                }

                // Full loop.
                status << "Code for " << char('m' + column) << " full remainder"
                       << status_stream::endl;
                if (!descend(layoutExt, true)) goto failed;
                inside ? jmpi(1, rdone) : done();

                // Remainder handling.
                for (int r = N - 1; r >= 0; r--) {
                    int q0 = r * fragSize;
                    int q1 = std::min<int>(q0 + fragSize, unroll);

                    status << "Code for " << char('m' + column)
                           << " remainders " << q0 + 1 << " - " << q1
                           << status_stream::endl;

                    mark(rlabels[r]);

                    if (!handleRemainderFP(q0, q1)) goto failed;
                }

                if (inside) mark(rdone);
            } else {
                // SIMT control flow version.
                Label labelRem, labelRemDone, labelDone;

                cmp(16 | ge | state.flagAP, remainder, uint16_t(unroll));
                if_(16 | state.flagAP, labelRem, labelDone);

                status << "Code for " << char('m' + column) << " full remainder"
                       << status_stream::endl;
                if (!descend(layoutExt, true)) goto failed;

                else_(16, labelDone);
                mark(labelRem);

                for (int q0 = 0; q0 < unroll; q0 += fragSize) {
                    int q1 = std::min<int>(q0 + fragSize, unroll);

                    cmp(16 | le | state.flagAP, remainder, uint16_t(q0));
                    goto12(16 | state.flagAP, labelRemDone);
                    status << "Code for " << char('m' + column)
                           << " remainders " << q0 + 1 << " - " << q1
                           << status_stream::endl;

                    if (!handleRemainderFP(q0, q1)) goto failed;
                }

                mark(labelRemDone);
                join(16);

                mark(labelDone);
                endif(16);
            }
        }
    }

    // Success!
    success = true;
failed:

    mark(lEnd);
    success ? appendCurrentStream() : discardStream();

    if (!inside && strategy.C.atomic) freeEAtomicAddRegs(state);

    return success;
}

// Alternate code path for C remainder handling, based on a simple double loop
//  and indirect addressing.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doAlternateCRemainder(COperation op,
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    auto Tc = problem.Tc, Tc_ext = problem.Tc_ext;
    int C_count = (op == COperation::UpdateStore) ? state.C_count : 1;
#define FOR_EACH_C for (int q = 0; q < C_count; q++)
#define FOR_EACH_C_REV for (int q = C_count - 1; q >= 0; q--)

    bool lateYLoopCheck = false;

    bool surface = !problem.C.base.isStateless();
    bool loadOnly = (op == COperation::Load);

    // C must be a single range for now.
    if (state.C_regs[0].ranges.size() != 1) stub();

    // Vector length in inner loop.
    const auto nbytes = 64;
    auto nec = nbytes / Tc;

    // 1- and 2-byte types must be padded to 4 bytes.
    bool byte_access = (Tc_ext.size() < 4);
    if (byte_access) nec = nbytes >> 2;

    // 8-byte+ types can use scattered qword. Only atomic for now.
    bool qword = !(Tc_ext.size() & 7) && strategy.C.atomic;
    int rshift = qword ? 3 : 2; // log2(data stride in regs)
    int rsimd = 64 >> rshift;

    auto &block0 = state.C_layout[0];
    bool cColMajorMem = isColMajor(problem.C.layout);
    bool cColMajorReg = block0.colMajor;
    bool transpose = (cColMajorReg != cColMajorMem);

    // x is the contiguous dimension (in registers), y is the other dimension.
    auto LoopX = cColMajorReg ? LoopM : LoopN;
    auto LoopY = cColMajorReg ? LoopN : LoopM;

    // Check the layout:
    //  - nx must be divisible by 2 (unpacked) GRFs, unless x unroll is < 2 GRFs,
    //      or there's an extra GRF at the end of C.
    //  - register offsets must be in a uniform 2D grid
    //  - all blocks must share same ordering (row/column major).
    int16_t xByteInc = 0, yByteInc = 0;
    bool cAtEnd = (state.C_regs[0][state.C_regs[0].getLen() - 1].getBase() + 1)
            >= strategy.GRFs;

    for (auto &block : state.C_layout) {
        if (block.colMajor != block0.colMajor) stub();

        int nx = cColMajorReg ? block.nr : block.nc;
        int ny = cColMajorReg ? block.nc : block.nr;
        int ox = cColMajorReg ? block.offsetR : block.offsetC;
        int oy = cColMajorReg ? block.offsetC : block.offsetR;

        ox /= nec;

        if ((nx & (nec - 1)) && cAtEnd) stub();

        if (xByteInc == 0 && nx > nec) xByteInc = nec * Tc;
        if (yByteInc == 0 && ny > 1) yByteInc = block.ld * Tc;

        if (block.offsetBytes != ox * xByteInc + oy * yByteInc) {
            if (xByteInc == 0 && ox > 0)
                xByteInc = (block.offsetBytes - oy * yByteInc) / ox;
            else if (yByteInc == 0 && oy > 0)
                yByteInc = (block.offsetBytes - ox * xByteInc) / oy;
            else
                stub();
        }
    }

    // Claim flags.
    state.raVFlag.claim(f0[0]);
    state.raVFlag.claim(f0[1]);
    state.raVFlag.claim(f1[0]);

    // Clear f0[1] for any16h trick.
    if (problem.fused && !lateYLoopCheck) mov(1, f0[1], uint16_t(0));

    // Update C with scattered accesses.
    // Get mask and set up header.
    GRFRange header[2];
    auto hregs = (surface ? 1 : 2) * (qword ? 1 : 2);
    FOR_EACH_C header[q] = state.ra.alloc_range(hregs);
    Subregister temp = state.ra.alloc_sub<uint32_t>();
    Subregister mask = state.ra.alloc_sub<uint32_t>();
    Subregister xIndex = state.remainders[LoopX];

    GRF indexVec, ivContig, ivScatter;

    indexVec = state.ra.alloc();
    indexVec.setType(DataType::w);
    mov(8, indexVec[0](1), Immediate::uv(0, 1, 2, 3, 4, 5, 6, 7));
    if (rsimd > 8)
        mov(8, indexVec[8](1), Immediate::uv(8, 9, 10, 11, 12, 13, 14, 15));

    auto oshift = std::min<int>(rshift, Tc_ext.log2Size());

    // Prepare x mask in f1.0 and prepare header for loads/stores.
    if (Tc_ext.size() > 4) {
        mulConstant(1, temp, xIndex, uint16_t(Tc_ext.size() >> rshift));
        xIndex = temp;
    }

    ivScatter = indexVec;
    bool splitScatter = transpose && (Tc_ext.log2Size() > rshift);
    if (splitScatter) {
        ivContig = state.ra.alloc();
        ivContig.setType(DataType::w);
        auto shift = Tc_ext.log2Size() - rshift;
        auto m = (1 << shift) - 1;

        asr(16, ivScatter, indexVec, uint16_t(shift));
        mov(16, ivContig,
                Immediate::uv((0 & m) << rshift, (1 & m) << rshift,
                        (2 & m) << rshift, (3 & m) << rshift, (4 & m) << rshift,
                        (5 & m) << rshift, (6 & m) << rshift,
                        (7 & m) << rshift));
    }

    add(1, temp, xIndex, int16_t(-1));
    FOR_EACH_C transpose
            ? mul(rsimd, header[q][0].d(), state.inputs.ldc[q], ivScatter)
            : shl(rsimd, header[q][0].d(), indexVec, uint16_t(oshift));
    FOR_EACH_C if (splitScatter)
            add(rsimd, header[q][0].d(), header[q][0].d(), ivContig);

    int hs = 1;
    bool header4 = !qword && !surface;
    int neq = elementsPerGRF(hw, DataType::uq);

    and_(1, temp, ~temp, uint16_t(rsimd - 1));
    FOR_EACH_C surface
            ? add(rsimd, header[q][0].d(), header[q][0].d(), state.effC[q])
            : header4 ? eadd(8, header[q][2].uq(), header[q][hs].d(0)(hs),
                      state.effC[q], strategy, state)
                      : noop();
    mov(1, mask, uint16_t((1 << rsimd) - 1));
    FOR_EACH_C if (!surface) eadd(2 * neq, header[q][0].uq(),
            header[q][0].d(0)(hs), state.inputs.C[q], strategy, state);
    shr(1, f1[0], mask, temp);

    state.ra.safeRelease(mask);
    state.ra.safeRelease(temp);
    state.ra.safeRelease(ivContig);

    // Synthesize double loop updating 2 GRFs (indirectly addressed) at a time.
    GRF ix = state.ra.alloc();
    Subregister ix_init = state.ra.alloc_sub<uint16_t>();
    Subregister iy = state.ra.alloc_sub<int16_t>();
    Subregister cXInc[2], cYInc[2];
    FOR_EACH_C cYInc[q] = state.ra.alloc_sub<int32_t>();
    Label yLoop, xLoop;
    GRFRange Cacc = state.ra.alloc_range(2);
    GRFRange CaccSwap {};
    GRFRange Cload
            = state.ra.alloc_range(2, getHint(HintType::CLoad, strategy));

    if (transpose) FOR_EACH_C {
            cXInc[q] = state.ra.alloc_sub<int32_t>();
            mulConstant(1, cXInc[q], state.inputs.ldc[q], nec);
        }

    add(1, ix_init, state.remainders[LoopX], int16_t(-1));
    mov(1, iy, state.remainders[LoopY]);
    shr(1, ix_init, ix_init, uint16_t(log2(nec)));
    mov(1, a0[0], state.C_regs[0][0].getBase() * GRF::bytes(hw));

    add(1, cYInc[0], ix_init, uint16_t(1));
    mulConstant(1, cYInc[0], cYInc[0],
            uint16_t(nec * (!transpose ? Tc_ext.size() : 1)));
    if (!transpose)
        FOR_EACH_C_REV add(1, cYInc[q], -cYInc[0], state.inputs.ldc[q]);
    else {
        FOR_EACH_C_REV mul(1, cYInc[q], state.inputs.ldc[q], cYInc[0].w());
        FOR_EACH_C_REV add(1, cYInc[q], -cYInc[q], uint16_t(Tc_ext.size()));
    }

    mark(yLoop);
    mov<uint16_t>(16, ix, ix_init);
    if (!lateYLoopCheck) add(1 | gt | f0[1], iy, iy, int16_t(-1));
    mov(1, a0[1], a0[0]);

    mark(xLoop);
    add<int16_t>(16 | ge | f0[0], ix, ix, int16_t(-1));

    // Update. The anyv is a trick to use the generated m mask (f1.0) on the last
    //  iteration of the loop, and no mask (0xFFFF) on the other iterations.
    InstructionModifier mod;
    mod = mod | f0[0] | anyv;

    if (!loadOnly) switch (state.Tacc.size()) {
            case 1: mov<uint32_t>(16, Cacc, indirect[a0[1]].ub()); break;
            case 2: mov<uint32_t>(16, Cacc, indirect[a0[1]].uw()); break;
            default: mov<uint32_t>(16, Cacc, indirect[a0[1]]); break;
        }

    if (strategy.C.atomic) {
        // Atomic update. Requires beta = 1, alpha prescaled.
        if (!problem.alpha1() && !problem.beta1()) stub();
        if (C_count > 1) stub();
        if (op != COperation::UpdateStore) stub();

        std::vector<RegisterBlock> layout {1};
        auto &block = layout[0];
        block.ebytes = qword ? 8 : Tc_ext.real().size();
        block.simdSize = rsimd;
        block.clearFlag();
        block.bytes = 64;
        block.extra = 1;
        block.log2GRFBytes = GRF::log2Bytes(hw);

        allocEAtomicAddRegs(hw, Tc_ext, layout, problem.C, state, f1[1]);

        Label labelEndAtomic;
        if_(16 | mod, labelEndAtomic);
        setDefaultNoMask(false);
        atomicAddMatrixBlock(Tc_ext, Cacc, block, problem.C, strategy.C,
                header[0], problem, strategy, state);
        setDefaultNoMask(true);
        mark(labelEndAtomic);
        endif(16);

        freeEAtomicAddRegs(state, f1[1]);
    } else {
        // Late C conversion, if needed.
        auto originalTacc = state.Tacc;
        if (problem.needsTsConvert() && state.Tacc != problem.Ts) {
            convert(Cacc, state.Tacc, problem.Ts, problem, strategy, state);
            state.Tacc = problem.Ts;
        }

        // Regular update.
        if (loadOnly || !problem.beta0()) {
            doReadSuppressionWA(strategy, state);
            byte_access ? load(16 | mod, Cload, scattered_byte(Tc_ext.size()),
                    problem.C.base, header[0])
                        : !surface ? load(16 | mod, Cload, scattered_dword(),
                                  problem.C.base, header[0])
                                   : load(16 | mod, Cload,
                                           surface_dword(ChannelMask::r),
                                           problem.C.base, header[0]);
        }

        if (!loadOnly) {
            auto Tc_out = (op == COperation::UpdateStore) ? problem.Tc_ext
                                                          : problem.Tc;
            if (!problem.beta0())
                convert(Cload, problem.Tc_ext, state.Tacc, problem, strategy,
                        state);
            updateC(Cacc, CaccSwap, Cload, problem, strategy, state);
            convert(Cacc, state.Tacc, Tc_out, problem, strategy, state);
        }

        // Indirect send operands don't seeem to be working on Gen9:
        // store(16 | mod, scattered_dword(), problem.C.base, header, indirect[a0[1]]);

        if (op != COperation::UpdateStore) {
            auto src = (op == COperation::Load) ? Cload : Cacc;
            switch (Tc.size()) {
                case 1:
                    mov<uint32_t>(16 | mod, indirect[a0[1]].ub(), src);
                    break;
                case 2:
                    mov<uint32_t>(16 | mod, indirect[a0[1]].uw(), src);
                    break;
                default: mov<uint32_t>(16 | mod, indirect[a0[1]], src); break;
            }
        } else
            FOR_EACH_C {
                byte_access ? store(16 | mod, scattered_byte(Tc_ext.size()),
                        problem.C.base, header[q], Cacc)
                            : !surface
                                ? store(16 | mod, scattered_dword(),
                                        problem.C.base, header[q], Cacc)
                                : store(16 | mod, surface_dword(ChannelMask::r),
                                        problem.C.base, header[q], Cacc);
            }

        state.Tacc = originalTacc;
    }

    add(1, a0[1], a0[1], xByteInc);
    if (!transpose) {
        uint16_t inc = nec * Tc_ext;
        if (!surface) {
            FOR_EACH_C eadd<uint64_t>(std::min(2 * neq, rsimd), header[q][0],
                    header[q][0], inc, strategy, state);
            if (header4)
                FOR_EACH_C eadd<uint64_t>(
                        8, header[q][2], header[q][2], inc, strategy, state);
        } else
            FOR_EACH_C add<uint32_t>(rsimd, header[q][0], header[q][0], inc);
    } else {
        if (!surface) {
            FOR_EACH_C eadd<uint64_t>(std::min(2 * neq, rsimd), header[q][0],
                    header[q][0], cXInc[q], strategy, state);
            if (header4)
                FOR_EACH_C eadd<uint64_t>(8, header[q][2], header[q][2],
                        cXInc[q], strategy, state);
        } else
            FOR_EACH_C add<uint32_t>(
                    rsimd, header[q][0], header[q][0], cXInc[q]);
    }

    // Bottom of x loop.
    //  Fused threads must use SIMT control flow instructions.
    problem.fused ? simtDoWhileLoop(16 | f0[0], xLoop) : jmpi(1 | f0[0], xLoop);

    if (lateYLoopCheck) add(1 | gt | f0[1], iy, iy, int16_t(-1));
    add(1, a0[0], a0[0], yByteInc);
    if (!surface) {
        FOR_EACH_C eadd<uint64_t>(std::min(2 * neq, rsimd), header[q][0],
                header[q][0], cYInc[q], strategy, state);
        if (header4)
            FOR_EACH_C eadd<uint64_t>(
                    8, header[q][2], header[q][2], cYInc[q], strategy, state);
    } else
        FOR_EACH_C add<uint32_t>(rsimd, header[q][0], header[q][0], cYInc[q]);

    // Bottom of y loop.
    //  The any16h is a trick: only the lowest bit of f0[1] is updated when decrementing iy,
    //  but we want to apply it to all channels.
    problem.fused ? simtDoWhileLoop(16 | f0[1] | any16h, yLoop)
                  : jmpi(1 | f0[1], yLoop);

    // Cleanup.
    state.raVFlag.release(f0[0]);
    state.raVFlag.release(f0[1]);
    state.raVFlag.release(f1[0]);

    state.ra.safeRelease(indexVec);
    state.ra.safeRelease(Cload);
    state.ra.safeRelease(CaccSwap);
    state.ra.safeRelease(Cacc);
    FOR_EACH_C state.ra.safeRelease(cXInc[q]);
    FOR_EACH_C state.ra.safeRelease(cYInc[q]);
    state.ra.safeRelease(iy);
    state.ra.safeRelease(ix);
    state.ra.safeRelease(ix_init);
    FOR_EACH_C state.ra.safeRelease(header[q]);

#undef FOR_EACH_C
}

// Prepare for GEMM k loop with m/n masked A/B accesses. Returns true if ka_lda/kb_ldb need recalculating.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmPrepMaskedAB(
        const GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    bool recalc = false;
    bool shrinkUK = false;
    if (!problem.A.padded
            && (strategy.remHandling[LoopM] != RemainderHandling::Ignore)) {
        shrinkUK = true;
        if (strategy.ka_load > strategy.ka_load_masked) {
            status << "Downgrading ka_load: " << strategy.ka_load << " -> "
                   << strategy.ka_load_masked << status_stream::endl;
            strategy.ka_load = strategy.ka_load_masked;
            recalc = true;
        }
        // Avoid access patterns that can't be handled by masking.
        if (problem.A.layout == MatrixLayout::T
                && !isTransposing(strategy.A.accessType))
            strategy.A.accessType = problem.A.base.isStateless()
                    ? AccessType::Scattered
                    : AccessType::ChannelScattered;
        else if (problem.A.layout != MatrixLayout::T
                && isTransposing(strategy.A.accessType))
            strategy.A.accessType = AccessType::Block;
    }
    if (!problem.B.padded
            && (strategy.remHandling[LoopN] != RemainderHandling::Ignore)) {
        shrinkUK = true;
        if (strategy.kb_load > strategy.kb_load_masked) {
            status << "Downgrading kb_load: " << strategy.kb_load << " -> "
                   << strategy.kb_load_masked << status_stream::endl;
            strategy.kb_load = strategy.kb_load_masked;
            recalc = true;
        }
        // Avoid access patterns that can't be handled by masking.
        if (problem.B.layout == MatrixLayout::N
                && !isTransposing(strategy.B.accessType))
            strategy.B.accessType = problem.B.base.isStateless()
                    ? AccessType::Scattered
                    : AccessType::ChannelScattered;
        else if (problem.B.layout != MatrixLayout::N
                && isTransposing(strategy.B.accessType))
            strategy.B.accessType = AccessType::Block;
    }
    if (shrinkUK && (strategy.unrollK_masked > 0)
            && (strategy.unroll[LoopK] > strategy.unrollK_masked)) {
        status << "Downgrading k unroll: " << strategy.unroll[LoopK] << " -> "
               << strategy.unrollK_masked << status_stream::endl;
        strategy.unroll[LoopK] = strategy.unrollK_masked;
    }
    return recalc;
}

// Generate the GEMM kernel body. If it fails (due to excessive masking, say), return false.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmBody(
        GEMMProblem problem, GEMMStrategy strategy, GEMMState state) {
    bool a2D = strategy.A.address2D;
    bool b2D = strategy.B.address2D;
    bool c2D = strategy.C.address2D;

    // Release variables that are no longer needed.
    if (!a2D && !c2D) state.ra.safeRelease(state.i0);
    if (!b2D && !c2D) state.ra.safeRelease(state.j0);
    if (!a2D && !b2D) state.ra.safeRelease(state.h0);
    if (!strategy.altCRemainder) releaseFusedRemainders(state);
    state.ra.safeRelease(state.remaindersWG[LoopM]);
    state.ra.safeRelease(state.remaindersWG[LoopN]);

    // If A/B are masked, check if we need to change ka_load/kb_load. If so, recalculate lda_ka/ldb_kb.
    if (gemmPrepMaskedAB(problem, strategy, state))
        gemmCalcIncrements(problem, strategy, state);

    // Try generating kernel body with current strategy.
    bool success = false;
    pushStream();
    try {
        success = gemmBodyInternal(problem, strategy, state);
    } catch (...) { lastException = std::current_exception(); }
    success ? appendCurrentStream() : discardStream();

    return success;
}

// Allocate nreg registers in chunks of a given size.
static inline GRFMultirange chunkAlloc(int nreg, int chunk, Bundle hint,
        BundleGroup mask, CommonState &state) {
    GRFMultirange r;
    for (; nreg > 0; nreg -= chunk) {
        auto nr = std::min(nreg, chunk);
        r.ranges.push_back(state.ra.alloc_range(nr, hint, mask));
    }
    return r;
}

static inline GRFMultirange chunkAlloc(
        int nreg, int chunk, Bundle hint, CommonState &state) {
    return chunkAlloc(nreg, chunk, hint, BundleGroup::AllBundles(), state);
}

// Allocate register ranges for A/B/C.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmAllocRegs(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    // Summary: order of allocations is important.
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    int nea = elementsPerGRF(hw, Ta);
    int neb = elementsPerGRF(hw, Tb);

    auto A_copies = strategy.A_copies;
    auto B_copies = strategy.B_copies;
    int A_regCount = getRegCount(state.A_layout);
    int Ar_regCount = getRegCount(state.Ar_layout);
    int A1_regCount = strategy.ka_repack ? Ar_regCount : A_regCount;
    int B_regCount = getRegCount(state.B_layout);
    int Br_regCount = getRegCount(state.Br_layout);
    int B1_regCount = strategy.kb_repack ? Br_regCount : B_regCount;
    int C_regCountPerComponent = getRegCount(state.C_layout);
    int C_regCount = Tc.components() * C_regCountPerComponent;
    GRFMultirange C_regs;

    bool globalCM = isLayoutColMajor(state.C_layout);

    auto hintA0 = globalCM ? HintType::A0 : HintType::A0Broadcast;
    auto hintA1 = globalCM ? HintType::A1 : HintType::A1Broadcast;
    auto hintB0 = !globalCM ? HintType::B0 : HintType::B0Broadcast;
    auto hintB1 = !globalCM ? HintType::B1 : HintType::B1Broadcast;

    auto &V_regs = globalCM ? state.A_regs : state.B_regs;
    auto &Vr_regs = globalCM ? state.Ar_regs : state.Br_regs;
    auto V_copies = globalCM ? A_copies : B_copies;
    auto V_regCount = globalCM ? A_regCount : B_regCount;
    auto Vr_regCount = globalCM ? Ar_regCount : Br_regCount;
    auto &N_regs = !globalCM ? state.A_regs : state.B_regs;
    auto &Nr_regs = !globalCM ? state.Ar_regs : state.Br_regs;
    auto N_copies = !globalCM ? A_copies : B_copies;
    auto N_regCount = !globalCM ? A_regCount : B_regCount;
    auto Nr_regCount = !globalCM ? Ar_regCount : Br_regCount;

    state.C_accCount
            = strategy.cAccumulators ? AccumulatorRegister::count(hw) : 0;

    state.A_regs.resize(A_copies);
    state.B_regs.resize(B_copies);

    switch (strategy.registerScheme) {
        case GEMMStrategy::CSeparate: {
            // Standard allocation (Gen9-11). A and B allocated together in lower half of registers.
            // Interleave allocation of A and B to minimize wasted registers. Test the waters to find out
            //  whether to try bank 0 or 1 first.
            int bases[2];
            for (int bank = 0; bank < 2; bank++) {
                auto r = state.ra.alloc_range(4, Bundle(bank, Bundle::any));
                bases[bank] = r.getBase();
                state.ra.safeRelease(r);
            }

            // Order of the banks.
            int banks[2];
            banks[0] = (bases[1] < bases[0]) ? 1 : 0;
            banks[1] = 1 - banks[0];

            // Allocate all the registers needed from bank 0, then all the registers needed from bank 1.
            for (int bank : banks) {
                if (getHint(hintA0, strategy).bank_id == bank) {
                    for (int copy = 0; copy < A_copies; copy++)
                        state.A_regs[copy] = state.ra.alloc_range(
                                A_regCount, getHint(hintA0, strategy));
                    if (state.broadcast && !globalCM)
                        state.broadcast_regs = state.ra.alloc_range(
                                alignup_pow2(strategy.fmaSIMD, nea) / nea,
                                getHint(hintA0, strategy));
                    if (Ar_regCount > 0)
                        state.Ar_regs = state.ra.alloc_range(
                                Ar_regCount, getHint(hintA0, strategy));
                }

                if (getHint(hintA1, strategy).bank_id == bank)
                    if (strategy.duplicateA)
                        state.A1_regs = state.ra.alloc_range(
                                A1_regCount, getHint(hintA1, strategy));

                if (getHint(hintB0, strategy).bank_id == bank) {
                    for (int copy = 0; copy < B_copies; copy++)
                        state.B_regs[copy] = state.ra.alloc_range(
                                B_regCount, getHint(hintB0, strategy));
                    if (state.broadcast && globalCM)
                        state.broadcast_regs = state.ra.alloc_range(
                                alignup_pow2(strategy.fmaSIMD, neb) / neb,
                                getHint(hintB0, strategy));
                    if (Br_regCount > 0)
                        state.Br_regs = state.ra.alloc_range(
                                Br_regCount, getHint(hintB0, strategy));
                }

                if (getHint(hintB1, strategy).bank_id == bank)
                    if (strategy.duplicateB)
                        state.B1_regs = state.ra.alloc_range(
                                B1_regCount, getHint(hintB1, strategy));
            }

            C_regs = state.ra.alloc_range(C_regCount - state.C_accCount,
                    getHint(HintType::C, strategy));
            break;
        }
        case GEMMStrategy::ACB:
            if (state.broadcast && !globalCM)
                state.broadcast_regs = state.ra.alloc_range(
                        alignup_pow2(strategy.fmaSIMD, nea) / nea,
                        getHint(hintA0, strategy));

            if (strategy.duplicateA && (A_regCount & 1)) {
                // When each A chunk has an odd number of GRFs, interleave A0/A1 allocations to avoid fragmentation.
                state.A_regs[0] = state.ra.alloc_range(
                        A_regCount, getHint(hintA0, strategy));
                state.A1_regs = state.ra.alloc_range(
                        A1_regCount, getHint(hintA1, strategy));
                for (int copy = 1; copy < A_copies; copy++)
                    state.A_regs[copy] = state.ra.alloc_range(
                            A_regCount, getHint(hintA0, strategy));
            } else {
                for (int copy = 0; copy < A_copies; copy++)
                    state.A_regs[copy] = state.ra.alloc_range(
                            A_regCount, getHint(hintA0, strategy));
                if (strategy.duplicateA)
                    state.A1_regs = state.ra.alloc_range(
                            A1_regCount, getHint(hintA1, strategy));
            }
            if (Ar_regCount > 0)
                state.Ar_regs = state.ra.alloc_range(
                        Ar_regCount, getHint(hintA0, strategy));

            C_regs = state.ra.alloc_range(C_regCount - state.C_accCount,
                    getHint(HintType::C, strategy));

            if (strategy.duplicateB && (B_regCount & 1)) {
                // Similarly for B.
                state.B_regs[0] = state.ra.alloc_range(
                        B_regCount, getHint(hintB0, strategy));
                state.B1_regs = state.ra.alloc_range(
                        B1_regCount, getHint(hintB1, strategy));
                for (int copy = 1; copy < B_copies; copy++)
                    state.B_regs[copy] = state.ra.alloc_range(
                            B_regCount, getHint(hintB0, strategy));
            } else {
                for (int copy = 0; copy < B_copies; copy++)
                    state.B_regs[copy] = state.ra.alloc_range(
                            B_regCount, getHint(hintB0, strategy));
                if (strategy.duplicateB)
                    state.B1_regs = state.ra.alloc_range(
                            B1_regCount, getHint(hintB1, strategy));
            }
            if (Br_regCount > 0)
                state.Br_regs = state.ra.alloc_range(
                        Br_regCount, getHint(hintB0, strategy));

            if (state.broadcast && globalCM)
                state.broadcast_regs = state.ra.alloc_range(
                        alignup_pow2(strategy.fmaSIMD, neb) / neb,
                        getHint(hintB0, strategy));
            break;
        case GEMMStrategy::BCA:
            if (state.broadcast && !globalCM)
                state.broadcast_regs = state.ra.alloc_range(
                        alignup_pow2(strategy.fmaSIMD, nea) / nea,
                        getHint(hintA0, strategy));

            if (strategy.duplicateB && (B_regCount & 1)) {
                // When each B chunk has an odd number of GRFs, interleave B0/B1 allocations to avoid fragmentation.
                state.B_regs[0] = state.ra.alloc_range(
                        B_regCount, getHint(hintB0, strategy));
                state.B1_regs = state.ra.alloc_range(
                        B1_regCount, getHint(hintB1, strategy));
                for (int copy = 1; copy < B_copies; copy++)
                    state.B_regs[copy] = state.ra.alloc_range(
                            B_regCount, getHint(hintB0, strategy));
            } else {
                for (int copy = 0; copy < B_copies; copy++)
                    state.B_regs[copy] = state.ra.alloc_range(
                            B_regCount, getHint(hintB0, strategy));
                if (strategy.duplicateB)
                    state.B1_regs = state.ra.alloc_range(
                            B1_regCount, getHint(hintB1, strategy));
            }
            if (Br_regCount > 0)
                state.Br_regs = state.ra.alloc_range(
                        Br_regCount, getHint(hintB0, strategy));

            C_regs = state.ra.alloc_range(C_regCount - state.C_accCount,
                    getHint(HintType::C, strategy));

            if (strategy.duplicateA && (A_regCount & 1)) {
                // Similarly for A.
                state.A_regs[0] = state.ra.alloc_range(
                        A_regCount, getHint(hintA0, strategy));
                state.A1_regs = state.ra.alloc_range(
                        A1_regCount, getHint(hintA1, strategy));
                for (int copy = 1; copy < A_copies; copy++)
                    state.A_regs[copy] = state.ra.alloc_range(
                            A_regCount, getHint(hintA0, strategy));
            } else {
                for (int copy = 0; copy < A_copies; copy++)
                    state.A_regs[copy] = state.ra.alloc_range(
                            A_regCount, getHint(hintA0, strategy));
                if (strategy.duplicateA)
                    state.A1_regs = state.ra.alloc_range(
                            A1_regCount, getHint(hintA1, strategy));
            }
            if (Ar_regCount > 0)
                state.Ar_regs = state.ra.alloc_range(
                        Ar_regCount, getHint(hintA0, strategy));

            if (state.broadcast && globalCM)
                state.broadcast_regs = state.ra.alloc_range(
                        alignup_pow2(strategy.fmaSIMD, neb) / neb,
                        getHint(hintB0, strategy));
            break;
        case GEMMStrategy::VNC: {
            if (hw < HW::Xe_LP) stub();
            // Xe+. Assign non-broadcast input matrix (V), then broadcast input matrix (N), then C.
            auto unrollVBytes = strategy.unroll[globalCM ? LoopM : LoopN]
                    * (globalCM ? Ta.size() : Tb.size());
            auto unrollNBytes = strategy.unroll[globalCM ? LoopN : LoopM]
                    * (globalCM ? Tb.size() : Ta.size());
            auto regUnrollV = div_up(unrollVBytes, GRF::bytes(hw));
            auto regUnrollN = div_up(unrollNBytes, GRF::bytes(hw));
            auto hintV = getHint(HintType::A0, strategy);
            auto hintN = getHint(
                    (regUnrollN == 1) ? HintType::A0 : HintType::A0Broadcast,
                    strategy); // Put V and N in same bundle if we can avoid N<->C conflicts.
            auto hintC = getHint(HintType::C, strategy);
            GRFRange tempPadding;

            for (int copy = 0; copy < V_copies; copy++)
                V_regs[copy] = state.ra.alloc_range(V_regCount, hintV);
            if (Vr_regCount > 0)
                Vr_regs = state.ra.alloc_range(Vr_regCount, hintV);

            N_regs[0] = state.ra.alloc_range(N_regCount, hintN);

            // Check if A * B outer product 0 has a bank conflict. If so, move N to avoid this.
            auto stride = Bundle(0, 0).stride(hw);
            auto offN = (N_regs[0][0].getBase() - V_regs[0][0].getBase())
                    & (stride - 1);
            auto offNMin = offN - ((regUnrollV - 1) & ~1);
            auto offNMax = offN + regUnrollN - 1;
            if (offNMax >= stride) offNMax -= stride, offNMin -= stride;
            if (offNMin <= 0) {
                unsigned obAlign = 1;
                if (hintN.bank_id != Bundle::any) obAlign *= 2;
                offNMax = alignup_pow2(offNMax, obAlign);
                safeReleaseRanges(N_regs[0], state);
                tempPadding = state.ra.alloc_range(offNMax, hintN);
                N_regs[0] = state.ra.alloc_range(N_regCount, hintN);
            }

            for (int copy = 1; copy < N_copies; copy++)
                N_regs[copy] = state.ra.alloc_range(N_regCount, hintN);
            if (Nr_regCount > 0)
                Nr_regs = state.ra.alloc_range(Nr_regCount, hintN);

            state.ra.safeRelease(tempPadding);

            C_regs = state.ra.alloc_range(C_regCount - state.C_accCount, hintC);
            break;
        }
        case GEMMStrategy::ABInterleave: {
            // Xe+. Interleave A and B, place C afterward.
            if (hw < HW::Xe_LP) stub();
            auto chunk = Bundle(0, 0).stride(hw) >> 1;

            // Test allocation. Put A earlier if it has more registers.
            int A_regTotal = A_regCount * A_copies + Ar_regCount;
            int B_regTotal = B_regCount * B_copies + Br_regCount;
            auto hintA = getHint(HintType::A0, strategy);
            auto hintB = getHint(HintType::B0, strategy);
            auto hintC = getHint(HintType::C, strategy);
            auto testA = state.ra.alloc_range(8, hintA);
            auto testB = state.ra.alloc_range(8, hintB);
            if ((testA.getBase() < testB.getBase())
                    == (A_regTotal < B_regTotal))
                std::swap(hintA, hintB);
            state.ra.safeRelease(testA);
            state.ra.safeRelease(testB);

            for (int copy = 0; copy < A_copies; copy++)
                state.A_regs[copy]
                        = chunkAlloc(A_regCount, chunk, hintA, state);
            if (Ar_regCount > 0)
                state.Ar_regs = chunkAlloc(Ar_regCount, chunk, hintA, state);
            for (int copy = 0; copy < B_copies; copy++)
                state.B_regs[copy]
                        = chunkAlloc(B_regCount, chunk, hintB, state);
            if (Br_regCount > 0)
                state.Br_regs = chunkAlloc(Br_regCount, chunk, hintB, state);
            C_regs = state.ra.alloc_range(C_regCount - state.C_accCount, hintC);
            break;
        }
    }

    // Assign C_regs, adding in GRFs (in place of accumulators) to use later.
    // Also split into two halves (regular and swapped real/imag parts) for complex.
    state.C_regs.resize(Tc.components());

    auto it = C_regs.ranges.begin();
    int off = -state.C_accCount;
    for (int comp = 0; comp < Tc.components(); comp++) {
        for (int todo = C_regCountPerComponent; todo > 0;) {
            int left = it->getLen() - off;
            int take = std::min(left, todo);
            state.C_regs[comp].ranges.push_back(
                    GRFRange(it->getBase() + off, take));
            todo -= take;
            off += take;
            if (off >= it->getLen()) off = 0, it++;
        }
    }

    // Allocate registers for SLM copies.
    state.Ai_regs.resize(strategy.slmCopies);
    state.Bi_regs.resize(strategy.slmCopies);
    if (strategy.slmA)
        for (int q = 0; q < strategy.slmCopies; q++)
            state.Ai_regs[q]
                    = state.ra.alloc_range(getRegCount(state.Ai_layout));
    if (strategy.slmB)
        for (int q = 0; q < strategy.slmCopies; q++)
            state.Bi_regs[q]
                    = state.ra.alloc_range(getRegCount(state.Bi_layout));

    // Allocate registers for A/B sums.
    state.As_regs = state.ra.alloc_range(getRegCount(state.As_layout));
    state.Bs_regs = state.ra.alloc_range(getRegCount(state.Bs_layout));

    // Allocate multiplication temporaries for Gen9 IGEMM, in pairs.
    if (isGen9IGEMM(hw, Ta, Tb, Tc)) {
        auto &temps = state.tempMul_regs;
        for (int ntemp = 0; ntemp < 2; ntemp++) {
            auto range = state.ra.try_alloc_range(2);
            if (range.isValid())
                temps.push_back(range);
            else if (temps.empty())
                throw out_of_registers_exception();
            else
                break;
        }
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmAllocAoBoRegs(
        bool forceAlloc, const GEMMStrategy &strategy, GEMMState &state) {
    bool allocAo = false, allocBo = false;

    if (forceAlloc) {
        allocAo = strategy.slmA && !state.allocedAo && !state.A_slmSplitM;
        allocBo = strategy.slmB && !state.allocedBo && !state.B_slmSplitN;
    } else {
        if (strategy.slmA && state.Ao_regs.empty() && !state.aioShare) {
            auto nreg = getRegCount(state.Ao_layout);
            auto &defaultRegs = state.A_regs[0];
            allocAo = (defaultRegs.getLen() < nreg);

            if (!allocAo) state.Ao_regs = defaultRegs;
        }

        if (strategy.slmB && state.Bo_regs.empty() && !state.bioShare) {
            auto nreg = getRegCount(state.Bo_layout);
            auto &defaultRegs = state.B_regs[0];
            allocBo = (defaultRegs.getLen() < nreg);

            if (!allocBo) state.Bo_regs = defaultRegs;
        }
    }

    if (allocAo) {
        state.allocedAo = true;
        state.Ao_regs = state.ra.alloc_range(getRegCount(state.Ao_layout));
    }

    if (allocBo) {
        state.allocedBo = true;
        state.Bo_regs = state.ra.alloc_range(getRegCount(state.Bo_layout));
    }
}

// Prepare layout for row/column sum matrices, and any needed auxiliary registers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::makeSumLayout(bool column, Type Tsrc,
        const vector<RegisterBlock> &srcLayout, Type Tdst,
        vector<RegisterBlock> &dstLayout, const CommonStrategy &strategy,
        CommonState &state) {
    bool canDP4A = (hw >= HW::Xe_LP) && one_of(Tsrc, Type::s8, Type::u8)
            && one_of(Tdst, Type::s32, Type::u32);
    bool cm = isLayoutColMajor(srcLayout);
    bool hReduce = (column == cm);
    bool needAll1s = false;
    int m, n;

    getLayoutDims(srcLayout, m, n);
    auto &rdim = column ? m : n;

    if (hReduce) {
        if (canDP4A && hasFullCrosspack(srcLayout, 1)) {
            rdim /= 4;
            needAll1s = true;
            if (rdim & 1) rdim <<= 1; // Ensure dp4a dest offset is even.
        }
    } else {
        if (canDP4A && hasFullCrosspack(srcLayout, 4)) needAll1s |= (rdim >= 4);
        rdim = 1;
    }

    makeUnbackedRegLayout(Tdst, dstLayout, m, n, cm, 1);

    // Prepare all-1s immediate for dp4a.
    if (needAll1s && state.all1s.isInvalid()) {
        state.all1s = state.ra.alloc_sub(
                Tdst.ngen(), getHint(HintType::LongTerm, strategy));
        mov(1, state.all1s, 0x01010101);
    }
}

// Accumulate row/column sums.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::accumulateSum(bool column, Type Tsrc,
        const GRFMultirange &srcRegs, const vector<RegisterBlock> &srcLayout,
        Type Tdst, const GRFMultirange &dstRegs,
        const vector<RegisterBlock> &dstLayout, const CommonStrategy &strategy,
        CommonState &state) {
    bool canDP4A = (hw >= HW::Xe_LP) && one_of(Tsrc, Type::s8, Type::u8)
            && one_of(Tdst, Type::s32, Type::u32);

    bool cm = isLayoutColMajor(srcLayout);
    if (cm != isLayoutColMajor(dstLayout)) stub();

    int m, n;
    getLayoutDims(srcLayout, m, n);

    // x: consecutive dimension in src; y: strided dimension in src
    auto nx = cm ? m : n;
    auto ny = cm ? n : m;

    // Two cases to handle:
    //   hReduce = false:  Good case; no reduction. Sum is vector of size mx1 or 1xn.
    //   hReduce = true:   Bad case; needs reduction later, although with dp4a some reduction can be done now.
    bool hReduce = (column == cm);

    int yinc = 1;
    int reduce = (canDP4A && hReduce) ? 4 : 1;
    if (nx % reduce) stub();

    for (int y = 0; y < ny; y += yinc) {
        for (int x = 0; x < nx;) {
            int isrc, jsrc, idst, jdst, nsrc, ndst;
            const RegisterBlock *blockSrc, *blockDst;

            isrc = cm ? x : y;
            jsrc = cm ? y : x;
            if (!hReduce) {
                idst = cm ? x : 0;
                jdst = cm ? 0 : x;
            } else {
                idst = cm ? x / reduce : y;
                jdst = cm ? y : x / reduce;
            }

            Subregister srcBase = findBlockReg(
                    Tsrc, srcLayout, isrc, jsrc, srcRegs, nsrc, blockSrc);
            Subregister dstBase = findBlockReg(
                    Tdst, dstLayout, idst, jdst, dstRegs, ndst, blockDst);
            auto ne = std::min(
                    {nsrc / reduce, ndst, elementsPerGRF(hw, Tdst) * 2});

            auto src = srcBase(blockSrc->crosspack);
            auto dst = dstBase(blockDst->crosspack);

            if (canDP4A) {
                auto srcDP4A
                        = Tsrc.isSigned() ? srcBase.d()(1) : srcBase.ud()(1);
                if (!hReduce && blockSrc->crosspack == 4) {
                    yinc = std::min(ny - y, 4);
                    if (yinc == 4)
                        dp4a(ne, dst, dst, srcDP4A, state.all1s);
                    else if (yinc == 1)
                        add(ne, dst, srcBase(4), dst);
                    else
                        dp4a(ne, dst, dst, srcDP4A,
                                0x01010101 & ((1 << (yinc * 8)) - 1));
                } else if (hReduce && blockSrc->crosspack == 1) {
                    if (Tsrc.isSigned())
                        dp4a(ne, dst, dst, srcDP4A, state.all1s);
                    else {
                        // Workaround for suspected HW issue.
                        dst.setType(DataType::ud);
                        dp4a(ne, dst, dst, srcDP4A, state.all1s.ud());
                    }
                }
            } else
                add(ne, dst, dst, src);

            x += ne * reduce;
        }
    }
}

// Horizontally add intermediate sums if needed.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::horizontalAdd(bool column, Type T,
        const GRFMultirange &regs, vector<RegisterBlock> &layout) {
    bool cm = isLayoutColMajor(layout);
    if (cm != column) return; // Nothing to do.

    int m, n;
    getLayoutDims(layout, m, n);

    int nx = cm ? m : n;
    int ny = cm ? n : m;
    int ne = elementsPerGRF(hw, T);

    for (int chunk = roundup_pow2(nx) >> 1; chunk > 0; chunk >>= 1) {
        for (int y = 0; y < ny; y++) {
            for (int x = chunk; x < (chunk * 2) && x < nx;) {
                int i = cm ? x : y;
                int j = cm ? y : x;
                int ns, nb;
                const RegisterBlock *block;
                Subregister shifted
                        = findBlockReg(T, layout, i, j, regs, ns, block);

                ns = std::min(ns, chunk);
                (cm ? i : j) -= chunk;
                Subregister base
                        = findBlockReg(T, layout, i, j, regs, nb, block);

                auto dest = base;
                if (chunk == 1) dest = regs[y / ne].sub(y % ne, T.ngen());

                add(ns, dest(1), base(1), shifted(1));
                x += ns;
            }
        }
    }

    (cm ? m : n) = 1;
    makeUnbackedRegLayout(T, layout, m, n, !cm, 1);
}

// Combine individual threads' A/B sums for SLM copy kernels.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmFinalizeSums(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    if (problem.abOffset != ABOffset::Calc) return true;
    if (!strategy.slmA && !strategy.slmB) return true;

    auto Tc = problem.Tc;
    auto unrollM = strategy.unroll[LoopM];
    auto unrollN = strategy.unroll[LoopN];
    bool ok = true;

    GRFMultirange *ABs_regs[2] = {&state.As_regs, &state.Bs_regs};
    bool AB_slmSplitMN[2] = {state.A_slmSplitM, state.B_slmSplitN};
    vector<RegisterBlock> *ABs_layout[2] = {&state.As_layout, &state.Bs_layout};

    vector<RegisterBlock> ABs_layoutSLM[2];
    MatrixAddressing ABs_SLM[2];
    MatrixAddressingStrategy ABs_strategySLM[2];
    MatrixAddressingStrategy ABs_strategySLMAtomic[2];
    vector<GRFRange> ABs_addrs[2];
    GRF temp = state.ra.alloc();
    FlagRegister leader[2];
    Subregister ABs_base[2];

    if (state.r0_info.isARF()) stub();
    GRF r0_info {state.r0_info.getBase()};

    // Plan:
    //   1) First thread of each m/n-block (leader) stores its sums in SLM; barrier
    //   2) Remaining threads atomically add their sums to the first; barrier
    //   3) All threads read final sums
    // For scattered SLM write kernels, threads have accumulated disjoint parts
    //  of the sums, so the second step isn't needed. However, each thread needs
    //  to do a horizontal reduction first.

    // Wait for previous SLM reads to complete.
    // In the meantime, finish sum reduction if necessary.
    if (hw >= HW::Gen11) slmfence(temp, r0_info);
    barriersignal(temp, r0_info);

    if (strategy.slmA && state.A_slmSplitM)
        horizontalAdd(false, Tc, state.As_regs, state.As_layout);
    if (strategy.slmB && state.B_slmSplitN)
        horizontalAdd(true, Tc, state.Bs_regs, state.Bs_layout);

    barrierwait();

    auto step1 = [&](bool isB, int r, int c) {
        ABs_SLM[isB].setAlignment(r * c * Tc);
        ABs_SLM[isB].base = AddressBase::createSLM();
        ABs_SLM[isB].crosspack = 1;
        ABs_SLM[isB].layout = !isB ? MatrixLayout::Pc : MatrixLayout::Pr;
        ABs_SLM[isB].packSize = r * c;
        ABs_SLM[isB].padded = true;
        // Use pseudoblock to share address registers between regular and atomic accesses.
        ABs_strategySLMAtomic[isB].accessType = AB_slmSplitMN[isB]
                ? AccessType::Block
                : AccessType::PseudoBlock;
        ABs_strategySLMAtomic[isB].atomic = !AB_slmSplitMN[isB];
        ABs_strategySLM[isB] = ABs_strategySLMAtomic[isB];
        ABs_strategySLM[isB].atomic = false;

        ok = ok
                && getRegLayout(Tc, ABs_layoutSLM[isB], r, c, false, false,
                        true, true, ScatterSIMD::Default, 0, 0, ABs_SLM[isB],
                        ABs_strategySLM[isB])
                && matchLayouts(Tc, ABs_layoutSLM[isB], *ABs_layout[isB]);

        Subregister adjBase = ABs_base[isB] = state.ra.alloc_sub<uint32_t>();
        uint16_t slmOffset = (isB && strategy.slmA)
                ? (unrollM * strategy.wg[LoopM] * Tc)
                : 0;

        !isB ? mulConstant(1, ABs_base[isB], state.lidM, unrollM * Tc)
             : mulConstant(1, ABs_base[isB], state.lidN, unrollN * Tc);

        if (slmOffset != 0) add(1, ABs_base[isB], ABs_base[isB], slmOffset);

        if (AB_slmSplitMN[isB]) {
            adjBase = state.ra.alloc_sub<uint32_t>();
            !isB ? mulConstant(1, adjBase, state.lidN, state.ma_slm * Tc)
                 : mulConstant(1, adjBase, state.lidM, state.nb_slm * Tc);
            add(1, adjBase, adjBase, ABs_base[isB]);
        }

        allocAddrRegs(ABs_addrs[isB], ABs_layoutSLM[isB], ABs_SLM[isB],
                ABs_strategySLM[isB], state);
        setupAddr(Tc, ABs_addrs[isB], adjBase, ABs_layoutSLM[isB],
                Subregister(), ABs_SLM[isB], ABs_strategySLM[isB], strategy,
                state);

        if (AB_slmSplitMN[isB]) state.ra.safeRelease(adjBase);

        Label labelNoStore;
        if (!AB_slmSplitMN[isB]) {
            leader[isB] = state.raVFlag.alloc();
            cmp(16 | eq | leader[isB], !isB ? state.lidN : state.lidM, 0);
            if_(16 | leader[isB], labelNoStore);
        }
        storeMatrix(*ABs_regs[isB], ABs_layoutSLM[isB], ABs_SLM[isB],
                ABs_strategySLM[isB], ABs_addrs[isB], strategy, state);
        if (!AB_slmSplitMN[isB]) {
            mark(labelNoStore);
            endif(16);
        }
    };

    bool barrier2 = false;
    auto step2 = [&](bool isB) {
        Label labelNoAdd;
        if_(16 | ~leader[isB], labelNoAdd);
        atomicAddMatrix(Tc, *ABs_regs[isB], ABs_layoutSLM[isB], ABs_SLM[isB],
                ABs_strategySLMAtomic[isB], ABs_addrs[isB], problem, strategy,
                state);
        mark(labelNoAdd);
        endif(16);
        barrier2 = true;
    };

    auto step3 = [&](bool isB, int r, int c) {
        if (AB_slmSplitMN[isB]) {
            safeReleaseRanges(ABs_addrs[isB], state);
            ABs_SLM[isB].packSize = r * c;
            ABs_SLM[isB].setAlignment(r * c * Tc);
            ABs_strategySLM[isB].accessType = AccessType::Block;
            ok = ok
                    && getRegLayout(Tc, ABs_layoutSLM[isB], r, c, false, false,
                            false, true, ScatterSIMD::Default, 0, 0,
                            ABs_SLM[isB], ABs_strategySLM[isB]);

            auto nregs = getRegCount(ABs_layoutSLM[isB]);
            if (nregs > ABs_regs[isB]->getLen()) {
                safeReleaseRanges(*ABs_regs[isB], state);
                *ABs_regs[isB] = state.ra.alloc_range(nregs);
            }

            allocAddrRegs(ABs_addrs[isB], ABs_layoutSLM[isB], ABs_SLM[isB],
                    ABs_strategySLM[isB], state);
            setupAddr(Tc, ABs_addrs[isB], ABs_base[isB], ABs_layoutSLM[isB],
                    Subregister(), ABs_SLM[isB], ABs_strategySLM[isB], strategy,
                    state);
        }
        loadMatrix(*ABs_regs[isB], ABs_layoutSLM[isB], ABs_SLM[isB],
                ABs_strategySLM[isB], ABs_addrs[isB], strategy, state);
        *ABs_layout[isB] = std::move(ABs_layoutSLM[isB]);
    };

    if (strategy.slmA) step1(false, state.ma_slm, 1);
    if (strategy.slmB) step1(true, 1, state.nb_slm);

    slmBarrier(temp, r0_info);

    if (strategy.slmA && !state.A_slmSplitM) step2(false);
    if (strategy.slmB && !state.B_slmSplitN) step2(true);

    if (barrier2) slmBarrier(temp, r0_info);

    if (strategy.slmA) step3(false, unrollM, 1);
    if (strategy.slmB) step3(true, 1, unrollN);

    state.ra.safeRelease(temp);
    state.ra.safeRelease(ABs_base[0]);
    state.ra.safeRelease(ABs_base[1]);
    state.raVFlag.safeRelease(leader[0]);
    state.raVFlag.safeRelease(leader[1]);
    safeReleaseRanges(ABs_addrs[0], state);
    safeReleaseRanges(ABs_addrs[1], state);

    return ok;
}

// Convert register range to a new type.
// If types are different sizes, we assume that the smaller type's stride is the width
//  of the larger type.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::convert(const GRFMultirange &range, Type Told,
        Type Tnew, const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    if (Told == Tnew) return;

    if (hw == HW::Gen9 && Told == Type::f32 && !Tnew.isFP()) {
        // Gen9: round to nearest before downconvert (not done by mov).
        map(hw, Told, range, range, strategy,
                [&](int esize, GRF r, GRF _) { rnde(esize, r.f(), r.f()); });
    }

    int maxLS = std::max(Told.log2Size(), Tnew.log2Size());
    int hsOld = 1 << (maxLS - Told.log2Size());
    int hsNew = 1 << (maxLS - Tnew.log2Size());
    auto Tmax = (Told.size() < Tnew.size()) ? Tnew : Told;

    map(hw, Tmax, range, range, strategy, [&](int esize, GRF r, GRF _) {
        emov(esize, r.sub(0, Tnew.ngen())(hsNew), r.sub(0, Told.ngen())(hsOld),
                strategy);
    });
}

// Convert C accumulator registers to a new type. Returns true if successful, or false if old and new type are different sizes.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmConvertC(Type Tnew,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    auto Told = state.Tacc;
    int ncomp = (problem.Tc.isComplex() && state.cSwapActive) ? 2 : 1;

    if (Tnew.size() != Told.size()) return false;

    for (int comp = 0; comp < ncomp; comp++)
        convert(state.C_regs[comp], Told, Tnew, problem, strategy, state);

    state.Tacc = Tnew;

    return true;
}

// Perform beta scaling.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmBetaScale(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    Label labelBetaDone;

    auto Ts = problem.Ts;
    auto &betar = problem.beta_real;

    if (state.beta1.isValid()) {
        if (problem.fused) {
            cmp(16 | lt | state.flagAP, null.d(), state.beta1, int16_t(0));
            goto12(16 | state.flagAP, labelBetaDone);
        } else {
            cmp(1 | lt | state.flagAP, null.d(), state.beta1, int16_t(0));
            jmpi(1 | state.flagAP, labelBetaDone);
        }
    }

    gemmConvertC(problem.Ts, problem, strategy, state);

    if (betar != 1) {
        map(hw, Ts.real(), state.C_regs[0], state.C_regs[0], strategy,
                [&](int esize, GRF acc, GRF _) {
                    betar.fixed() ? mul(esize, acc, acc, cast(Ts.real(), betar))
                                  : mul(esize, acc, acc,
                                          betar.getRegAvoiding(hw, acc));
                });
    }

    gemmConvertC(problem.Tc, problem, strategy, state);

    mark(labelBetaDone);

    if (state.beta1.isValid() && problem.fused) join(16);
}

// Add fixed offset to C.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmFixedOffsetC(const Subregister &offset,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    map(hw, problem.Tc, state.C_regs[0], state.C_layout, strategy,
            [&](int simd, const RegData &r) { add(simd, r, r, offset); });
}

// Add row-wise or column-wise offsets to C, possibly multiplying by a scalar.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmVariableOffsetC(bool column,
        const GRFMultirange &offsets, const Subregister &scale,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state, vector<RegisterBlock> CO_layout) {
    auto Tc = problem.Tc;
    auto ne = elementsPerGRF(hw, Tc);
    auto globalCM = isLayoutColMajor(state.C_layout);
    auto unrollX = strategy.unroll[globalCM ? LoopM : LoopN];
    auto unrollY = strategy.unroll[globalCM ? LoopN : LoopM];
    auto crosspack = CO_layout.empty() ? 1 : CO_layout[0].crosspack;
    auto stride = (column == globalCM) ? 0 : crosspack;
    const GRFMultirange *offsetsPtr = &offsets;

    for (int y = 0; y < unrollY; y++) {
        for (int x = 0; x < unrollX;) {
            auto i = globalCM ? x : y;
            auto j = globalCM ? y : x;
            int nc;
            const RegisterBlock *C_block;
            Subregister C = findBlockReg(
                    Tc, state.C_layout, i, j, state.C_regs[0], nc, C_block);

            nc = std::min(nc, strategy.fmaSIMD / crosspack);
            auto nco = (column ? j : i) * crosspack;
            auto offBase = (*offsetsPtr)[nco / ne].sub(nco % ne, Tc.ngen());
            if (scale.isValid())
                mad(nc, C(1), C(1), offBase(stride), scale);
            else
                add(nc, C(1), C(1), offBase(stride));

            x += nc;
        }
    }
}

// Apply fixed/row-wise/column-wise C offset.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmApplyCOffset(bool row, bool column,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    auto Tc = problem.Tc;
    auto cor = row ? strategy.unroll[LoopM] : 1;
    auto coc = column ? strategy.unroll[LoopN] : 1;

    auto CO = problem.CO;
    std::vector<GRFRange> CO_addrs;
    std::vector<RegisterBlock> CO_layout;
    MatrixAddressingStrategy CO_strategy;
    std::vector<MaskAssignment> masks;
    CO_strategy.accessType = AccessType::Block;

    CO.layout = column ? MatrixLayout::T : MatrixLayout::N;

    auto remR = row && !problem.CO.padded;
    auto remC = column && !problem.CO.padded;

    if (!getRegLayout(Tc, CO_layout, cor, coc, remR, remC, false, true,
                ScatterSIMD::Default, 0, 0, CO, CO_strategy))
        return false;

    auto CO_regs = state.ra.alloc_range(getRegCount(CO_layout));

    allocAddrRegs(CO_addrs, CO_layout, CO, CO_strategy, state);
    setupAddr(Tc, CO_addrs, state.effCO, CO_layout, Subregister(), CO,
            CO_strategy, strategy, state);

    if (!assignMasks(CO_layout, LoopM, LoopN, masks, state)) {
        status << "Retrying with virtual flags." << status_stream::endl;
        allocVFlagStorage(strategy, state);
        if (!assignMasks(CO_layout, LoopM, LoopN, masks, state)) return false;
    }

    loadMasks(masks, state.remainders, state);
    loadMatrix(CO_regs, CO_layout, CO, CO_strategy, CO_addrs, strategy, state);
    releaseMaskAssignments(masks, state);

    if (row && column)
        stub();
    else if (!row && !column)
        gemmFixedOffsetC(
                CO_regs[0].sub(0, Tc.ngen()), problem, strategy, state);
    else
        gemmVariableOffsetC(column, CO_regs, Subregister(), problem, strategy,
                state, CO_layout);

    return true;
}

// Check kernel input for desired C offset and apply it.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmApplyCOffsetDispatch(
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    Label labelCOColumn, labelCORow, labelCODone;
    bool ok = true;

    if (state.flagSwizzle.isValid()) state.raVFlag.release(state.flagSwizzle);

    auto flagNonfinal = state.raVFlag.alloc();
    auto flagCOC = state.raVFlag.alloc();
    auto flagCOR = state.raVFlag.alloc();

    and_(1 | nz | flagNonfinal, null.ud(), state.inputs.flags,
            FlagNonfinalKBlock);
    and_(1 | nz | flagCOC, null.ud(), state.inputs.flags, FlagCOColumn);
    and_(1 | nz | flagCOR, null.ud(), state.inputs.flags, FlagCORow);
    jmpi(1 | flagNonfinal, labelCODone);
    jmpi(1 | flagCOC, labelCOColumn);
    jmpi(1 | flagCOR, labelCORow);

    state.raVFlag.safeRelease(flagNonfinal);
    state.raVFlag.safeRelease(flagCOC);
    state.raVFlag.safeRelease(flagCOR);

    if (state.flagSwizzle.isValid()) state.raVFlag.claim(state.flagSwizzle);

    status << "Applying fixed C offset" << status_stream::endl;
    ok = ok && gemmApplyCOffset(false, false, problem, strategy, state);
    jmpi(1, labelCODone);

    mark(labelCOColumn);
    status << "Applying column-wise C offset" << status_stream::endl;
    ok = ok && gemmApplyCOffset(false, true, problem, strategy, state);
    jmpi(1, labelCODone);

    mark(labelCORow);
    status << "Applying row-wise C offset" << status_stream::endl;
    ok = ok && gemmApplyCOffset(true, false, problem, strategy, state);

    mark(labelCODone);

    return ok;
}

// Load A/B sums from packed input data. Sums are stored at the end of each panel.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmLoadABOffset(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    if (problem.abOffset != ABOffset::Load) return true;

    auto Tc = problem.Tc;
    auto unrollM = strategy.unroll[LoopM];
    auto unrollN = strategy.unroll[LoopN];

    MatrixAddressing As = problem.A, Bs = problem.B;
    As.crosspack = 1;
    Bs.crosspack = 1;

    MatrixAddressingStrategy As_strategy, Bs_strategy;
    As_strategy.accessType = AccessType::Block;
    Bs_strategy.accessType = AccessType::Block;

    bool ok = true;
    ok = ok
            && getRegLayout(Tc, state.As_layout, unrollM, 1, false, false,
                    false, true, ScatterSIMD::Default, 0, 0, As, As_strategy);
    ok = ok
            && getRegLayout(Tc, state.Bs_layout, 1, unrollN, false, false,
                    false, true, ScatterSIMD::Default, 0, 0, Bs, Bs_strategy);
    if (!ok) return false;

    state.As_regs = state.ra.alloc_range(getRegCount(state.As_layout));
    state.Bs_regs = state.ra.alloc_range(getRegCount(state.Bs_layout));

    vector<GRFRange> As_addrs, Bs_addrs;
    allocAddrRegs(As_addrs, state.As_layout, As, As_strategy, state);
    allocAddrRegs(Bs_addrs, state.Bs_layout, Bs, Bs_strategy, state);

    Subregister As_base, Bs_base;
    As_base = state.ra.alloc_sub(state.effA.getType());
    Bs_base = state.ra.alloc_sub(state.effB.getType());

    mulConstant(1, As_base.ud(), state.inputs.lda, unrollM);
    mulConstant(1, Bs_base.ud(), state.inputs.ldb, unrollN);
    add(1, As_base.ud(), As_base.ud(), -unrollM * Tc);
    add(1, Bs_base.ud(), Bs_base.ud(), -unrollN * Tc);
    eadd(1, As_base, As_base.ud(), state.effA, strategy, state);
    eadd(1, Bs_base, Bs_base.ud(), state.effB, strategy, state);

    setupAddr(Tc, As_addrs, As_base, state.As_layout, Subregister(), As,
            As_strategy, strategy, state);
    setupAddr(Tc, Bs_addrs, Bs_base, state.Bs_layout, Subregister(), Bs,
            Bs_strategy, strategy, state);

    loadMatrix(state.As_regs, state.As_layout, As, As_strategy, As_addrs,
            strategy, state);
    loadMatrix(state.Bs_regs, state.Bs_layout, Bs, Bs_strategy, Bs_addrs,
            strategy, state);

    state.ra.safeRelease(As_base);
    state.ra.safeRelease(Bs_base);
    safeReleaseRanges(As_addrs, state);
    safeReleaseRanges(Bs_addrs, state);

    return true;
}

// Apply contributions from A/B offsets to C matrix, using previously loaded/computed
// A row sums and B column sums.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmApplyABOffset(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    if (problem.abOffset == ABOffset::None) return;

    // Two steps: (O = all-1s matrix)
    //   1) C += A * O * bo
    //   2) C += (O * B + bo * k) * ao
    auto temp = state.ra.alloc_sub(problem.Tc.ngen());
    mul(1, temp, state.inputs.k, state.inputs.bo);

    bool noFMA = (hw == HW::Gen9);
    if (noFMA) {
        map(hw, problem.Tc, state.Bs_regs, state.Bs_layout, strategy,
                [&](int ne, RegData r) { add(ne, r, r, temp); });
        map(hw, problem.Tc, state.As_regs, state.As_layout, strategy,
                [&](int ne, RegData r) { mul(ne, r, r, state.inputs.bo); });
        map(hw, problem.Tc, state.Bs_regs, state.Bs_layout, strategy,
                [&](int ne, RegData r) { mul(ne, r, r, state.inputs.ao); });
    } else {
        mul(1, temp, temp, state.inputs.ao);
        map(hw, problem.Tc, state.Bs_regs, state.Bs_layout, strategy,
                [&](int ne, RegData r) {
                    mad(ne, r, temp, r, state.inputs.ao);
                });
    }
    state.ra.safeRelease(temp);

    gemmVariableOffsetC(false, state.As_regs,
            noFMA ? Subregister() : state.inputs.bo, problem, strategy, state);
    gemmVariableOffsetC(
            true, state.Bs_regs, Subregister(), problem, strategy, state);

    safeReleaseRanges(state.As_regs, state);
    safeReleaseRanges(state.Bs_regs, state);
    state.ra.safeRelease(state.inputs.ao);
    state.ra.safeRelease(state.inputs.bo);
    state.As_layout.clear();
    state.Bs_layout.clear();
}

// Generate code for checking whether 32-bit address arithmetic can be used inside k loop.
// Assumes leading dimensions have not been shifted yet.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmCheck32(
        const GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    if (!strategy.checkAdd32) return;

    bool checkA = (problem.A.base.getModel() == ModelA64);
    bool checkB = (problem.B.base.getModel() == ModelA64);
    if (!checkA && !checkB) return;

    auto Ta = problem.Ta, Tb = problem.Tb;
    auto &m = state.inputs.m;
    auto &n = state.inputs.n;
    auto &k = state.inputs.k;
    auto &lda = state.inputs.lda;
    auto &ldb = state.inputs.ldb;
    auto temp1GRF = state.ra.alloc();
    auto temp2GRF = state.ra.alloc();
    auto temp1 = temp1GRF.ud(
            0); // Only need one :ud subregister. But GRF-align it for mach.
    auto temp2 = temp2GRF.ud(0);
    auto temp3 = temp2GRF.ud(4);
    auto flag = state.raVFlag.alloc();

    if (checkA) {
        mulConstant(1, temp1, lda, Ta.size());
        emad(1, temp2, state.effA.ud(), state.inputs.offsetA.ud(), Ta.size(),
                strategy, state);
        switch (problem.A
                        .layout) { // Conservatively estimate upper bound for size of A.
            case MatrixLayout::N: emul32High(1, temp1, temp1, k); break;
            case MatrixLayout::T: emul32High(1, temp1, temp1, m); break;
            case MatrixLayout::Pc: {
                if (strategy.fixedWG())
                    add(1, temp3, m,
                            uint16_t(strategy.wg[LoopM] * strategy.unroll[LoopM]
                                    - 1));
                else
                    emad(1, temp3, m, state.inputs.localSizeM,
                            strategy.unroll[LoopM], strategy, state);
                emul32High(1, temp1, temp1, temp3);
                break;
            }
            default: stub();
        }
        add(1 | ov | flag, temp2, acc0.ud(0), temp2);
        cmp(1 | ~flag | ne | flag, temp1, uint16_t(0));
    }

    if (checkB) {
        mulConstant(1, temp1, ldb, Tb.size());
        emad(1, temp2, state.effB.ud(), state.inputs.offsetB.ud(), Tb.size(),
                strategy, state);
        switch (problem.B.layout) {
            case MatrixLayout::T: emul32High(1, temp1, temp1, k); break;
            case MatrixLayout::N: emul32High(1, temp1, temp1, n); break;
            case MatrixLayout::Pr: {
                if (strategy.fixedWG())
                    add(1, temp3, n,
                            uint16_t(strategy.wg[LoopN] * strategy.unroll[LoopN]
                                    - 1));
                else
                    emad(1, temp3, n, state.inputs.localSizeN,
                            strategy.unroll[LoopN], strategy, state);
                emul32High(1, temp1, temp1, temp3);
                break;
            }
                add(1, temp3, n, uint16_t(strategy.unroll[LoopN] - 1));
                emul32High(1, temp1, temp1, temp3);
                break;
            default: stub();
        }
        InstructionModifier mod = 1;
        if (checkA) mod |= ~flag;
        add(mod | ov | flag, temp2, acc0.ud(0), temp2);
        cmp(1 | ~flag | ne | flag, temp1, uint16_t(0));
    }

    state.add64 = state.ra.alloc_sub<uint16_t>();
    mov(1, state.add64, flag);
    state.raVFlag.safeRelease(flag);

    state.ra.safeRelease(temp1GRF);
    temp1 = invalid;
    state.ra.safeRelease(temp2GRF);
    temp2 = invalid;
    temp3 = invalid;
}

// Increment A pointer after load, inside GEMM k loop.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doAIncrementInternal(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &A,
        const MatrixAddressingStrategy &A_strategy, int ka_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    if (ka_inc == 0)
        /* no-op */;
    else if (A_strategy.address2D)
        incDecAddr(addrs, Subregister(), 0, ka_inc, layout, A, A_strategy,
                strategy, state, problem.backward);
    else if (A.layout == MatrixLayout::N) {
        Subregister lda_ka;
        bool release = false;
        // Use cached lda * ka_inc if available, otherwise calculate on the fly.
        if (ka_inc == 1)
            lda_ka = state.inputs.lda;
        else if (ka_inc == state.ka_cached)
            lda_ka = state.lda_ka;
        else {
            lda_ka = state.ra.alloc_sub<int32_t>();
            emulConstant(1, lda_ka, state.inputs.lda, ka_inc, strategy, state);
            release = true;
        }
        incDecAddr(addrs, lda_ka, layout, A, A_strategy, strategy, state,
                problem.backward);
        if (release) state.ra.safeRelease(lda_ka);
    } else {
        int incA;
        switch (A.layout) {
            case MatrixLayout::Pc: incA = A.packSize * ka_inc; break;
            case MatrixLayout::T: incA = ka_inc; break;
            default: stub();
        }
        incDecAddr(addrs, uint16_t(incA * problem.Ta), layout, A, A_strategy,
                strategy, state, problem.backward);
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doAIncrementInternal(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &A,
        const MatrixAddressingStrategy &A_strategy,
        const MultishiftSubregister &ka_inc, const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    incDecAddr(addrs, ka_inc, layout, A, A_strategy, strategy, state,
            problem.backward);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::doAIncrement(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &A,
        const MatrixAddressingStrategy &A_strategy, I ka_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    doAIncrementInternal(
            layout, addrs, A, A_strategy, ka_inc, problem, strategy, state);
}

// A load for GEMM k loop.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doALoad(const GRFMultirange &regs,
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &A,
        const MatrixAddressingStrategy &A_strategy, const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    loadMatrix(regs, layout, A, A_strategy, addrs, strategy, state);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::doALoadInc(const GRFMultirange &regs,
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &A,
        const MatrixAddressingStrategy &A_strategy, I ka_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    doALoad(regs, layout, addrs, A, A_strategy, problem, strategy, state);
    doAIncrement(
            layout, addrs, A, A_strategy, ka_inc, problem, strategy, state);
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doBIncrementInternal(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &B,
        const MatrixAddressingStrategy &B_strategy, int kb_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    if (kb_inc == 0)
        /* no-op */;
    else if (B_strategy.address2D)
        incDecAddr(addrs, Subregister(), kb_inc, 0, layout, B, B_strategy,
                strategy, state, problem.backward);
    else if (B.layout == MatrixLayout::T) {
        Subregister ldb_kb;
        bool release = false;
        if (kb_inc == 1)
            ldb_kb = state.inputs.ldb;
        else if (kb_inc == state.kb_cached)
            ldb_kb = state.ldb_kb;
        else {
            ldb_kb = state.ra.alloc_sub<int32_t>();
            emulConstant(1, ldb_kb, state.inputs.ldb, kb_inc, strategy, state);
            release = true;
        }
        incDecAddr(addrs, ldb_kb, layout, B, B_strategy, strategy, state,
                problem.backward);
        if (release) state.ra.safeRelease(ldb_kb);
    } else {
        int incB;
        switch (B.layout) {
            case MatrixLayout::Pr: incB = B.packSize * kb_inc; break;
            case MatrixLayout::N: incB = kb_inc; break;
            default: stub();
        }
        incDecAddr(addrs, uint16_t(incB * problem.Tb), layout, B, B_strategy,
                strategy, state, problem.backward);
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doBIncrementInternal(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &B,
        const MatrixAddressingStrategy &B_strategy,
        const MultishiftSubregister &kb_inc, const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    incDecAddr(addrs, kb_inc, layout, B, B_strategy, strategy, state,
            problem.backward);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::doBIncrement(
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &B,
        const MatrixAddressingStrategy &B_strategy, I kb_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    doBIncrementInternal(
            layout, addrs, B, B_strategy, kb_inc, problem, strategy, state);
}

// B load for GEMM k loop.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::doBLoad(const GRFMultirange &regs,
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &B,
        const MatrixAddressingStrategy &B_strategy, const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    loadMatrix(regs, layout, B, B_strategy, addrs, strategy, state);
}

template <ngen::HW hw>
template <typename I>
void gemm_kernel_generator_t<hw>::doBLoadInc(const GRFMultirange &regs,
        const std::vector<RegisterBlock> &layout,
        const std::vector<ngen::GRFRange> &addrs, const MatrixAddressing &B,
        const MatrixAddressingStrategy &B_strategy, I kb_inc,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    doBLoad(regs, layout, addrs, B, B_strategy, problem, strategy, state);
    doBIncrement(
            layout, addrs, B, B_strategy, kb_inc, problem, strategy, state);
}

// Calculate Ai offset for SLM copies for this local ID.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmCalcAiOffset(Subregister dst,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        const GEMMState &state) {
    auto Ta = problem.Ta;
    switch (state.Ai.layout) {
        case MatrixLayout::Pc:
            mulConstant(1, dst, state.lidN, state.ma_slm * state.ka_slm * Ta);
            break;
        case MatrixLayout::T:
            if (state.A_slmSplitM) {
                mul(1, dst, state.inputs.lda, state.lidN);
                mulConstant(1, dst, dst, state.ma_slm);
            } else
                mulConstant(1, dst, state.lidN, state.ka_slm * Ta);
            break;
        case MatrixLayout::N:
            if (state.A_slmSplitM)
                mulConstant(1, dst, state.lidN, state.ma_slm * Ta);
            else {
                mul(1, dst, state.inputs.lda, state.lidN);
                mulConstant(1, dst, dst, state.ka_slm);
            }
            break;
        default: stub();
    }
}

// Calculate Bi offset for SLM copies for this local ID.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmCalcBiOffset(Subregister dst,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        const GEMMState &state) {
    auto Tb = problem.Tb;
    switch (state.Bi.layout) {
        case MatrixLayout::Pr:
            mulConstant(1, dst, state.lidM, state.nb_slm * state.kb_slm * Tb);
            break;
        case MatrixLayout::N:
            if (state.B_slmSplitN) {
                mul(1, dst, state.inputs.ldb, state.lidM);
                mulConstant(1, dst, dst, state.nb_slm);
            } else
                mulConstant(1, dst, state.lidM, state.kb_slm * Tb);
            break;
        case MatrixLayout::T:
            if (state.B_slmSplitN)
                mulConstant(1, dst, state.lidM, state.nb_slm * Tb);
            else {
                mul(1, dst, state.inputs.ldb, state.lidM);
                mulConstant(1, dst, dst, state.kb_slm);
            }
            break;
        default: stub();
    }
}

// Perform the body of the GEMM computation, updating a block of C.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmKLoop(int ka_repack_in, int kb_repack_in,
        bool lateKLoopCheck, GEMMProblem &problem, GEMMStrategy &strategy,
        GEMMState &state) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;

    Label lKLoopBegin, lKLoopCooldown, lKLoopCooldown1, lKLoopEnd;
    Label lKRemLoopBegin, lKRemLoopEntry, lKRemLoopReentry, lKRemLoopNoSLMLoad,
            lKRemLoopEnd;

    bool remainderK = strategy.remHandling[LoopK] != RemainderHandling::Ignore;
    bool cLoadAhead = strategy.cLoadAhead;
    auto opCount = outerProductCount(hw, problem, strategy);

    auto A_copies = strategy.A_copies;
    auto B_copies = strategy.B_copies;
    auto slmCopies = strategy.slmCopies;
    auto ka_repack = ka_repack_in;
    auto kb_repack = kb_repack_in;

    int slmCopyLoad = 0, slmCopyStore = 0;

    bool needBarrier = (strategy.slmBuffers > 0 || strategy.barrierFreq > 0);
    bool remFixup = false;

    // Get r0 information where needed.
    GRF r0_info;
    if (needBarrier) {
        if (state.r0_info.isARF()) stub();
        r0_info = GRF {state.r0_info.getBase()};
    }

    // Double-buffered SLM copy support.
    Subregister slmIncStoreStorage, slmIncLoadStorage;
    MultishiftSubregister slmAIncStore, slmBIncStore;
    MultishiftSubregister slmAIncLoad, slmBIncLoad;
    uint32_t slmIncLoadVals[2], slmIncStoreVals[2];

    if (strategy.slmBuffers == 2) {
        auto Ao_addrShift = strategy.slmA ? state.Ao_layout[0].addrShift : 0;
        auto Bo_addrShift = strategy.slmB ? state.Bo_layout[0].addrShift : 0;
        auto A_addrShift = state.A_layout[0].addrShift;
        auto B_addrShift = state.B_layout[0].addrShift;
        int slmAoInc = strategy.slmABufBlockSize(Ta, state) >> Ao_addrShift;
        int slmBoInc = strategy.slmBBufBlockSize(Tb, state) >> Bo_addrShift;
        int slmAInc = strategy.slmABufBlockSize(Ta, state) >> A_addrShift;
        int slmBInc = strategy.slmBBufBlockSize(Tb, state) >> B_addrShift;

        slmIncStoreStorage = state.ra.alloc_sub<uint32_t>();
        slmIncLoadStorage = state.ra.alloc_sub<uint32_t>();
        slmAIncStore.set(Ao_addrShift, slmIncStoreStorage.uw(0));
        slmBIncStore.set(Bo_addrShift, slmIncStoreStorage.uw(1));
        slmAIncLoad.set(A_addrShift, slmIncLoadStorage.uw(0));
        slmBIncLoad.set(B_addrShift, slmIncLoadStorage.uw(1));

        uint16_t kaByteInc = (strategy.ka_load * strategy.unroll[LoopM] * Ta)
                >> A_addrShift;
        uint16_t kbByteInc = (strategy.kb_load * strategy.unroll[LoopN] * Tb)
                >> B_addrShift;
        slmIncLoadVals[0]
                = uint16_t(kaByteInc) | (uint32_t(uint16_t(kbByteInc)) << 16);
        slmIncLoadVals[1] = uint16_t(kaByteInc - 2 * slmAInc)
                | (uint32_t(uint16_t(kbByteInc - 2 * slmBInc)) << 16);

        slmIncStoreVals[0]
                = uint16_t(+slmAoInc) | (uint32_t(uint16_t(+slmBoInc)) << 16);
        slmIncStoreVals[1]
                = uint16_t(-slmAoInc) | (uint32_t(uint16_t(-slmBoInc)) << 16);

        mov(1, slmIncStoreStorage, slmIncStoreVals[0]);
        mov(1, slmIncLoadStorage, slmIncLoadVals[0]);
    }

    // Copy loads.
    auto doSLMLoads = [&]() {
        status << "Local copy load" << status_stream::endl;
        if (strategy.slmA)
            doALoadInc(state.Ai_regs[slmCopyLoad], state.Ai_layout,
                    state.Ai_addrs, state.Ai, state.Ai_strategy,
                    strategy.unrollKSLM, problem, strategy, state);
        if (strategy.slmB)
            doBLoadInc(state.Bi_regs[slmCopyLoad], state.Bi_layout,
                    state.Bi_addrs, state.Bi, state.Bi_strategy,
                    strategy.unrollKSLM, problem, strategy, state);
        if (++slmCopyLoad >= slmCopies) slmCopyLoad = 0;
    };

    auto doRemainderSLMLoads = [&](bool copy) -> bool {
        status << "Local copy remainder load" << status_stream::endl;

        auto temp = state.ra.alloc_sub<int32_t>();
        bool delayInc = !copy && remFixup;
        bool success = true;

        if (strategy.slmA) {
            auto &Ai_regs = state.Ai_regs[slmCopyLoad];
            if (state.A_slmSplitM) {
                if (problem.abOffset == ABOffset::Calc)
                    zeroMatrix(Ai_regs, strategy);
                doALoadInc(Ai_regs, state.Ai_layout, state.Ai_addrs, state.Ai,
                        state.Ai_strategy, strategy.unrollKSLM, problem,
                        strategy, state);
            } else {
                vector<RegisterBlock> Ai_layout1;
                vector<GRFRange> Ai_addrs1;
                Label done;

                if (problem.backward && copy
                        && state.ka_slm > 1) { // Adjust pointer from main loop.
                    success &= getSubblocks(Ta, Ai_layout1, Ai_addrs1,
                            state.Ai_layout, state.Ai_addrs, true, 0, 1,
                            state.Ai.padded, state.Ai, state.Ai_strategy);
                    doAIncrement(Ai_layout1, Ai_addrs1, state.Ai,
                            state.Ai_strategy, 1 - state.ka_slm, problem,
                            strategy, state);
                }

                bool simtCF = problem.fused && (problem.fusedLoop == LoopN);

                if (simtCF) {
                    cmp(16 | gt | state.flagAP, state.K, state.ha0_slm);
                    add(1, temp, state.K, -state.ha0_slm);
                } else
                    add(1 | gt | state.flagAP, temp, state.K, -state.ha0_slm);

                if (problem.A.crosspack > 1
                        || problem.abOffset == ABOffset::Calc)
                    zeroMatrix(copy ? state.Ao_regs : Ai_regs, strategy);

                for (int hh = 0; hh < state.ka_slm; hh++) {
                    simtCF ? goto12(16 | ~state.flagAP, done)
                           : jmpi(1 | ~state.flagAP, done);
                    if ((hh + 1) < state.ka_slm)
                        cmp((simtCF ? 16 : 1) | gt | state.flagAP, temp,
                                int16_t(hh + 1));

                    int hh_eff
                            = problem.backward ? (state.ka_slm - 1 - hh) : hh;
                    int hh_src = copy ? 0 : hh_eff;
                    if (!copy || (hh == 0))
                        success &= getSubblocks(Ta, Ai_layout1, Ai_addrs1,
                                state.Ai_layout, state.Ai_addrs, true, hh_src,
                                hh_src + 1, state.Ai.padded, state.Ai,
                                state.Ai_strategy);

                    auto ka_inc = delayInc ? 0
                                           : !copy ? strategy.unrollKSLM
                                                   : ((hh + 1) != state.ka_slm)
                                            ? 1
                                            : problem.backward
                                                    ? strategy.unrollKSLM
                                                    : (strategy.unrollKSLM
                                                            - state.ka_slm + 1);
                    doALoadInc(Ai_regs, Ai_layout1, Ai_addrs1, state.Ai,
                            state.Ai_strategy, ka_inc, problem, strategy,
                            state);

                    if (copy)
                        copyRegisters(Ta, Ta, Ai_layout1, state.Ao_layout,
                                Ai_regs, state.Ao_regs, 0, hh_eff, false,
                                strategy, state);
                }
                mark(done);
                if (simtCF) join(16);

                if (delayInc)
                    doAIncrement(state.Ai_layout, state.Ai_addrs, state.Ai,
                            state.Ai_strategy, strategy.unrollKSLM, problem,
                            strategy, state);
            }
        }

        if (strategy.slmB) {
            auto &Bi_regs = state.Bi_regs[slmCopyLoad];
            if (state.B_slmSplitN) {
                if (problem.abOffset == ABOffset::Calc)
                    zeroMatrix(Bi_regs, strategy);
                doBLoadInc(Bi_regs, state.Bi_layout, state.Bi_addrs, state.Bi,
                        state.Bi_strategy, strategy.unrollKSLM, problem,
                        strategy, state);
            } else {
                vector<RegisterBlock> Bi_layout1;
                vector<GRFRange> Bi_addrs1;
                Label done;

                if (problem.backward && copy
                        && state.kb_slm > 1) { // Adjust pointer from main loop.
                    success &= getSubblocks(Tb, Bi_layout1, Bi_addrs1,
                            state.Bi_layout, state.Bi_addrs, false, 0, 1,
                            state.Bi.padded, state.Bi, state.Bi_strategy);
                    doBIncrement(Bi_layout1, Bi_addrs1, state.Bi,
                            state.Bi_strategy, 1 - state.kb_slm, problem,
                            strategy, state);
                }

                bool simtCF = problem.fused && (problem.fusedLoop == LoopM);

                if (simtCF) {
                    cmp(16 | gt | state.flagAP, state.K, state.hb0_slm);
                    add(1, temp, state.K, -state.hb0_slm);
                } else
                    add(1 | gt | state.flagAP, temp, state.K, -state.hb0_slm);

                if (problem.B.crosspack > 1
                        || problem.abOffset == ABOffset::Calc)
                    zeroMatrix(copy ? state.Bo_regs : Bi_regs, strategy);

                for (int hh = 0; hh < state.kb_slm; hh++) {
                    simtCF ? goto12(16 | ~state.flagAP, done)
                           : jmpi(1 | ~state.flagAP, done);
                    if ((hh + 1) < state.kb_slm)
                        cmp((simtCF ? 16 : 1) | gt | state.flagAP, temp,
                                int16_t(hh + 1));

                    int hh_eff
                            = problem.backward ? (state.kb_slm - 1 - hh) : hh;
                    int hh_src = copy ? 0 : hh_eff;
                    if (!copy || (hh == 0))
                        success &= getSubblocks(Tb, Bi_layout1, Bi_addrs1,
                                state.Bi_layout, state.Bi_addrs, false, hh_src,
                                hh_src + 1, state.Bi.padded, state.Bi,
                                state.Bi_strategy);

                    auto kb_inc = delayInc ? 0
                                           : !copy ? strategy.unrollKSLM
                                                   : ((hh + 1) != state.kb_slm)
                                            ? 1
                                            : problem.backward
                                                    ? strategy.unrollKSLM
                                                    : (strategy.unrollKSLM
                                                            - state.kb_slm + 1);
                    doBLoadInc(Bi_regs, Bi_layout1, Bi_addrs1, state.Bi,
                            state.Bi_strategy, kb_inc, problem, strategy,
                            state);

                    if (copy)
                        copyRegisters(Tb, Tb, Bi_layout1, state.Bo_layout,
                                Bi_regs, state.Bo_regs, hh_eff, 0, false,
                                strategy, state);
                }

                mark(done);
                if (simtCF) join(16);

                if (delayInc)
                    doBIncrement(state.Bi_layout, state.Bi_addrs, state.Bi,
                            state.Bi_strategy, strategy.unrollKSLM, problem,
                            strategy, state);
            }
        }

        if (strategy.slmA && state.A_slmSplitM && copy && !state.aioShare)
            copyRegisters(Ta, Ta, state.Ai_layout, state.Ao_layout,
                    state.Ai_regs[slmCopyLoad], state.Ao_regs, 0, 0, false,
                    strategy, state);
        if (strategy.slmB && state.B_slmSplitN && copy && !state.bioShare)
            copyRegisters(Tb, Tb, state.Bi_layout, state.Bo_layout,
                    state.Bi_regs[slmCopyLoad], state.Bo_regs, 0, 0, false,
                    strategy, state);

        if (++slmCopyLoad >= slmCopies) slmCopyLoad = 0;

        state.ra.safeRelease(temp);
        return success;
    };

    // Copy stores. Also does row/column sum calculations if needed.
    auto doSLMStores = [&](bool noCopy = false) {
        status << "Local copy store" << status_stream::endl;

        const auto &Ai_regs = state.Ai_regs[slmCopyStore];
        const auto &Bi_regs = state.Bi_regs[slmCopyStore];
        const auto &Ao_regs = state.Ao_regs.empty() ? Ai_regs : state.Ao_regs;
        const auto &Bo_regs = state.Bo_regs.empty() ? Bi_regs : state.Bo_regs;

        if (strategy.slmA && !state.aioShare && !noCopy)
            copyRegisters(Ta, Ta, state.Ai_layout, state.Ao_layout, Ai_regs,
                    state.Ao_regs, 0, 0, false, strategy, state);
        if (strategy.slmB && !state.bioShare && !noCopy)
            copyRegisters(Tb, Tb, state.Bi_layout, state.Bo_layout, Bi_regs,
                    state.Bo_regs, 0, 0, false, strategy, state);

        if (strategy.slmA)
            storeMatrix(Ao_regs, state.Ao_layout, state.Ao, state.Ao_strategy,
                    state.Ao_addrs, strategy, state);
        if (strategy.slmB)
            storeMatrix(Bo_regs, state.Bo_layout, state.Bo, state.Bo_strategy,
                    state.Bo_addrs, strategy, state);

        if (problem.abOffset == ABOffset::Calc) {
            if (strategy.slmA)
                accumulateSum(false, Ta, Ao_regs, state.Ao_layout, Tc,
                        state.As_regs, state.As_layout, strategy, state);
            if (strategy.slmB)
                accumulateSum(true, Tb, Bo_regs, state.Bo_layout, Tc,
                        state.Bs_regs, state.Bs_layout, strategy, state);
        }

        if (strategy.slmBuffers == 2) {
            if (strategy.slmA)
                incAddr(state.Ao_addrs, slmAIncStore, state.Ao_layout, state.Ao,
                        state.Ao_strategy, strategy, state);
            if (strategy.slmB)
                incAddr(state.Bo_addrs, slmBIncStore, state.Bo_layout, state.Bo,
                        state.Bo_strategy, strategy, state);
            xor_(1, slmIncStoreStorage, slmIncStoreStorage,
                    slmIncStoreVals[0] ^ slmIncStoreVals[1]);
        } else if (strategy.slmBuffers > 2)
            stub();

        if (++slmCopyStore >= slmCopies) slmCopyStore = 0;
    };

    // Reuse k/k0 for the loop counter, unless nested.
    //  - If k unroll > 1, the loop counter will offset by (unrollK - 1) during the main loop.
    // Then, unless we are assured positive loop count, check for zero main loop count.
    auto unrollK = strategy.unroll[LoopK];
    auto kInput = state.inputs.k;
    bool saveK = state.isNested || (problem.abOffset != ABOffset::None);
    auto outerK = state.K = saveK ? state.ra.alloc_sub<int32_t>() : kInput;

    // Split k counter into outer and inner counter for barriers.
    if (strategy.barrierFreq > 0) {
        state.K = state.ra.alloc_sub<int32_t>();
        min_(1, state.K, kInput, int32_t(strategy.barrierFreq));
        add(1 | sat, outerK.ud(), kInput.ud(), int16_t(-strategy.barrierFreq));
        kInput = state.K;
    }

    if (unrollK > 1) {
        // Bias loop counter by unrollK - 1.
        add(1 | le | state.flagAP, state.K, kInput, int16_t(1 - unrollK));
    } else if (!problem.kPositive) {
        // Check for 0 loop count.
        if (saveK)
            mov(1 | le | state.flagAP, state.K, kInput);
        else
            cmp(1 | le | state.flagAP, null.d(), kInput, int16_t(0));
    }

    // Zero out A/B sums if needed.
    if (problem.abOffset != ABOffset::None) {
        zeroMatrix(state.As_regs, strategy);
        zeroMatrix(state.Bs_regs, strategy);
    }

    // Zero out C, if not loading ahead of time.
    if (!cLoadAhead) {
        for (int i = 0; i < state.C_accCount; i += 2)
            mov<uint32_t>(2 * elementsPerGRF<uint32_t>(hw),
                    AccumulatorRegister(i), uint16_t(0));

        for (int comp = 0; comp < Tc.components(); comp++)
            zeroMatrix(state.C_regs[comp], strategy);
    }

    // Bail to remainder loop if no main loops.
    if (!problem.kPositive || (unrollK > 1)) jmpi(1 | state.flagAP, lKLoopEnd);

    // Warmups.
    int A_copy = A_copies - 1;
    int B_copy = B_copies - 1;
    bool needCooldown = false;
    bool peeledKLoop = false;

    // SLM copy warmups.
    switch (strategy.slmBuffers) {
        case 0: break;
        case 1: {
            for (int q = 0; q < slmCopies; q++)
                doSLMLoads();
            add(1 | le | state.flagAP, state.K, state.K, int16_t(-unrollK));
            doSLMStores();

            auto temp = state.ra.alloc();
            slmBarrier(temp, r0_info);
            state.ra.safeRelease(temp);

            needCooldown = peeledKLoop = true;
            break;
        }
        case 2: {
            if (slmCopies > 1) stub();

            doSLMLoads();
            add(1 | le | state.flagAP, state.K, state.K, int16_t(-unrollK));
            doSLMStores();
            jmpi(1 | state.flagAP, lKLoopCooldown1);
            doSLMLoads(); // todo move above store
            add(1 | le | state.flagAP, state.K, state.K, int16_t(-unrollK));
            doSLMStores();

            auto temp = state.ra.alloc();
            slmBarrier(temp, r0_info);
            state.ra.safeRelease(temp);

            needCooldown = peeledKLoop = true;
            break;
        }
        default: stub();
    }

    // A/B_copies warmups. First, do a warmup load of data needed for first loop.
    // Then, peel one k loop from the end for the cooldown loop and jump there if none left.
    if (A_copies > 1 || B_copies > 1) {
        if (!peeledKLoop)
            add(1 | le | state.flagAP, state.K, state.K, int16_t(-unrollK));

        for (int copy = 0; copy < std::max(A_copies, B_copies) - 1; copy++) {
            if (copy < A_copies - 1)
                doALoadInc(state.A_regs[copy], state.A_layout, state.A_addrs,
                        problem.A, strategy.A, strategy.ka_load, problem,
                        strategy, state);
            if (copy < B_copies - 1)
                doBLoadInc(state.B_regs[copy], state.B_layout, state.B_addrs,
                        problem.B, strategy.B, strategy.kb_load, problem,
                        strategy, state);
        }

        needCooldown = peeledKLoop = true;
    }

    if (needCooldown) jmpi(1 | state.flagAP, lKLoopCooldown);

    enum class KLoopType { Main, Cooldown, Remainder };

    // Lambda used in k loop body (workaround for GCC nested lambda bug)
    auto mov_lambda
            = [&](int esize, GRF ab1, GRF ab0) { mov(esize, ab1, ab0); };

    // k loop.
    auto kLoopBody = [&](const vector<RegisterBlock> &A_layout,
                             const vector<RegisterBlock> &B_layout,
                             const vector<GRFRange> &A_addrs,
                             const vector<GRFRange> &B_addrs, int unrollK,
                             int ka_load, int kb_load, int ka_repack,
                             int kb_repack, KLoopType type,
                             bool checkRem = false) {
        bool main = (type == KLoopType::Main);
        bool cooldown = (type == KLoopType::Cooldown);
        bool remLoop = (type == KLoopType::Remainder);
        bool unlockAP = false;
        bool saveRSWA = strategy.readSuppressionWA;
        Label skipLoad, done;

        if (checkRem) {
            unlockAP = !state.raVFlag.lock(state.flagAP);
            state.usePhysicalFlag(state.flagAP);
        }

        if (checkRem || (problem.abOffset == ABOffset::Calc)) {
            if (ka_repack) zeroMatrix(state.Ar_regs, strategy);
            if (kb_repack) zeroMatrix(state.Br_regs, strategy);
        }

        if (unrollK % problem.A.crosspack) stub();
        if (unrollK % problem.B.crosspack) stub();
        if (unrollK % slmCopies) stub();

        int ha = ka_load, hb = kb_load;
        int ha_repack = ka_repack, hb_repack = kb_repack;

        int hKLoopCheck = checkRem
                ? (unrollK - 1)
                : lateKLoopCheck ? (unrollK - std::min(ka_load, kb_load)) : 0;

        bool remaskA = !strategy.slmA && remLoop && (opCount > 1)
                && needsRemask(Ta, true, A_layout, strategy.A);
        bool remaskB = !strategy.slmB && remLoop && (opCount > 1)
                && needsRemask(Tb, false, B_layout, strategy.B);

        if (remaskA && remaskB && Tc.isInteger()) {
            // Only need to remask one operand for integer GEMMs. Choose the smaller one.
            if (strategy.unroll[LoopM] >= strategy.unroll[LoopN])
                remaskA = false;
            else
                remaskB = false;
        }

        if (remaskA || remaskB) {
            if (remaskA && remaskB && Ta.size() != Tb.size()) stub();
            if (problem.backward) stub();
            setupTeardownRemask(
                    remaskA ? Ta : Tb, true, unrollK, state.K, strategy, state);
        }

        // Check whether we might need read suppression workarounds for main A/B loads.
        bool rswaA = saveRSWA && (A_copies == 1)
                && ((ka_load <= opCount) || ka_repack) && hasMasking(A_layout);
        bool rswaB = saveRSWA && (B_copies == 1)
                && ((kb_load <= opCount) || kb_repack) && hasMasking(B_layout);

        bool lastLoadA = false, lastLoadB = false;
        bool newSumA = false, newSumB = false;

        for (int h = 0; h < unrollK;
                h++, ha++, hb++, ha_repack++, hb_repack++) {
            bool loadA = false, loadB = false;
            bool newA = false, newB = false;
            bool repackA = false, repackB = false;
            bool incA = false, incB = false;

            // SLM copy loads.
            if ((strategy.slmBuffers > 0) && (h % strategy.unrollKSLM == 0)
                    && main)
                doSLMLoads();

            // Maintain ha (= h % ka_load) and hb (= h & kb_load) counters.
            // These always count forward, even for backward GEMMs.
            if (ha == ka_load) {
                ha = 0;
                newA = true;
                lastLoadA = loadA
                        = !cooldown || (h <= (unrollK - (A_copies * ka_load)));
            }

            if (hb == kb_load) {
                hb = 0;
                newB = true;
                lastLoadB = loadB
                        = !cooldown || (h <= (unrollK - (B_copies * kb_load)));
            }

            // Similarly for ha_repack = h % ka_repack and kb_repack.
            if (ka_repack && (ha_repack == ka_repack)) {
                ha_repack = 0;
                repackA = true;
            }

            if (kb_repack && (hb_repack == kb_repack)) {
                hb_repack = 0;
                repackB = true;
            }

            // Check if it's time to increment A/B.
            incA = (ha
                           == ((strategy.delayABInc && (A_copies > 1))
                                           ? (ka_load >> 1)
                                           : 0))
                    && lastLoadA;
            incB = (hb
                           == ((strategy.delayABInc && (B_copies > 1))
                                           ? (kb_load >> 1)
                                           : 0))
                    && lastLoadB;

            // Remainder check, if needed.
            if (checkRem && (h > 0)) {
                if ((h % opCount) == 0) {
                    cmp(1 | gt | state.flagAP, state.K, uint16_t(h));
                    jmpi(1 | ~state.flagAP,
                            done); // Warning, trick: inverted logic so if we jump to done, flagAP is left as 0, and loop is exited.
                } else if (loadA || loadB) {
                    cmp(1 | le | state.flagAP, state.K, uint16_t(h));
                    jmpi(1 | state.flagAP, skipLoad);
                }
            }

            if (rswaA || rswaB) doReadSuppressionWA(strategy, state);
            strategy.readSuppressionWA = false;

            // Load A every ka_load loops, and increment A_copy.
            if (loadA)
                doALoad(state.A_regs[A_copy], A_layout, A_addrs, problem.A,
                        strategy.A, problem, strategy, state);

            if (incA) {
                auto ka_inc = ka_load;
                bool slmReturn = strategy.slmA
                        && (((h + ka_load * A_copies) % strategy.unrollKSLM)
                                < ka_load);

                if (slmReturn && (strategy.slmBuffers == 2))
                    doAIncrement(A_layout, A_addrs, problem.A, strategy.A,
                            slmAIncLoad, problem, strategy, state);
                else {
                    if (slmReturn)
                        ka_inc -= strategy.unrollKSLM * strategy.slmBuffers;
                    doAIncrement(A_layout, A_addrs, problem.A, strategy.A,
                            ka_inc, problem, strategy, state);
                }
            }

            if (ha == 0)
                if (++A_copy == A_copies) A_copy = 0;

            // Load B every kb_load loops, and increment B_copy.
            if (loadB)
                doBLoad(state.B_regs[B_copy], B_layout, B_addrs, problem.B,
                        strategy.B, problem, strategy, state);

            if (incB) {
                auto kb_inc = kb_load;
                bool slmReturn = strategy.slmB
                        && (((h + kb_load * B_copies) % strategy.unrollKSLM)
                                < kb_load);

                if (slmReturn && (strategy.slmBuffers == 2))
                    doBIncrement(B_layout, B_addrs, problem.B, strategy.B,
                            slmBIncLoad, problem, strategy, state);
                else {
                    if (slmReturn)
                        kb_inc -= strategy.unrollKSLM * strategy.slmBuffers;
                    doBIncrement(B_layout, B_addrs, problem.B, strategy.B,
                            kb_inc, problem, strategy, state);
                }
            }

            if (hb == 0)
                if (++B_copy == B_copies) B_copy = 0;

            strategy.readSuppressionWA = saveRSWA;

            // Remask A/B if needed.
            if (loadA && remaskA)
                remaskLayout(Ta, true, A_layout, state.A_regs[A_copy], strategy,
                        state, h);
            if (loadB && remaskB)
                remaskLayout(Tb, false, B_layout, state.B_regs[B_copy],
                        strategy, state, h);

            // Repack A/B every {ka,kb}_repack loops. When checking remainder, perform repack incrementally.
            repackA |= ((checkRem && loadA) && ka_repack);
            repackB |= ((checkRem && loadB) && kb_repack);
            if (repackA)
                copyRegisters(Ta, Ta, A_layout, state.Ar_layout,
                        state.A_regs[A_copy], state.Ar_regs, 0, ha_repack,
                        false, strategy, state);
            if (repackB)
                copyRegisters(Tb, Tb, B_layout, state.Br_layout,
                        state.B_regs[B_copy], state.Br_regs, hb_repack, 0,
                        false, strategy, state);

            auto &A_regs = ka_repack ? state.Ar_regs : state.A_regs[A_copy];
            auto &B_regs = kb_repack ? state.Br_regs : state.B_regs[B_copy];
            auto &Ar_layout = ka_repack ? state.Ar_layout : A_layout;
            auto &Br_layout = kb_repack ? state.Br_layout : B_layout;

            if (checkRem && ((h + 1) % opCount == 0)) {
                mark(skipLoad);
                skipLoad = Label {};
            }

            // Test loop counter now on first iteration (lateKLoopCheck == false)
            //  or after all loads complete (lateKLoopCheck == true)
            if (h == hKLoopCheck && !cooldown) {
                // Use the all-purpose flag for k loop query.
                add(1 | gt | state.flagAP, state.K, state.K, int16_t(-unrollK));
            }

            // When starting on fresh round of A data, duplicate if needed.
            if (newA && strategy.duplicateA)
                map<uint32_t>(hw, state.A1_regs, A_regs, strategy, mov_lambda);

            // Similarly for B.
            if (newB && strategy.duplicateB)
                map<uint32_t>(hw, state.B1_regs, B_regs, strategy, mov_lambda);

            // Accumulate A row sums and B column sums if needed, when new data arrives.
            if (problem.abOffset == ABOffset::Calc) {
                newSumA |= ka_repack ? repackA : newA;
                newSumB |= kb_repack ? repackB : newB;
                if ((h + 1) % opCount == 0) {
                    if (newSumA && !strategy.slmA)
                        accumulateSum(false, Ta, A_regs, Ar_layout, Tc,
                                state.As_regs, state.As_layout, strategy,
                                state);
                    if (newSumB && !strategy.slmB)
                        accumulateSum(true, Tb, B_regs, Br_layout, Tc,
                                state.Bs_regs, state.Bs_layout, strategy,
                                state);
                    newSumA = newSumB = false;
                }
            }

            // Do one outer product. For backward GEMMs, reverse ha and hb now.
            int ha_eff = problem.backward ? (ka_load - 1 - ha) : ha;
            int hb_eff = problem.backward ? (kb_load - 1 - hb) : hb;
            if (ka_repack) ha_eff %= ka_repack;
            if (kb_repack) hb_eff %= kb_repack;
            outerProduct(h, ha_eff, hb_eff, Ar_layout, Br_layout, A_regs,
                    B_regs, problem, strategy, state);

            // SLM copy stores.
            int hAdjustA = 0, hAdjustB = 0, hAdjust = 0;
            if (strategy.slmA) hAdjust = hAdjustA = ka_load * (A_copies - 1);
            if (strategy.slmB) hAdjust = hAdjustB = kb_load * (B_copies - 1);
            if (strategy.slmA && strategy.slmB && (hAdjustA != hAdjustB))
                stub();

            if (strategy.slmBuffers > 0
                    && ((h + 1 + hAdjust) % strategy.unrollKSLM) == 0) {
                // Toggle double-buffered SLM increment.
                if (strategy.slmBuffers == 2)
                    xor_(1, slmIncLoadStorage, slmIncLoadStorage,
                            slmIncLoadVals[0] ^ slmIncLoadVals[1]);

                if (!remLoop
                        && (!cooldown
                                || (h <= unrollK - strategy.unrollKSLM))) {
                    switch (strategy.slmBuffers) {
                        case 1:
                        case 2: {
                            auto temp = state.ra.alloc();
                            barrier(temp, r0_info);
                            doSLMStores();
                            if (hw >= HW::Gen11) {
                                slmfence(temp, r0_info);
                                mov<uint32_t>(8, null, temp);
                            }
                            if (strategy.slmBuffers == 1)
                                barrier(temp, r0_info);
                            state.ra.safeRelease(temp);
                            break;
                        }
                        default: stub();
                    }
                }
            }
        }

        if (checkRem && (unrollK > opCount)) mark(done);

        if (remaskA || remaskB)
            setupTeardownRemask(remaskA ? Ta : Tb, false, unrollK, state.K,
                    strategy, state);

        // Forget about active vflags.
        state.wipeActiveVFlags();

        if (unlockAP) state.raVFlag.unlock(state.flagAP);

        strategy.readSuppressionWA = saveRSWA;
    };

    if (lateKLoopCheck) state.raVFlag.unlock(state.flagAP);

    // Sync pipeline to avoid unnecessary SWSB dependencies in main loop.
    syncall();

    // Main k loop.
    mark(lKLoopBegin);
    {
        state.wipeActiveVFlags();

        kLoopBody(state.A_layout, state.B_layout, state.A_addrs, state.B_addrs,
                unrollK, strategy.ka_load, strategy.kb_load, ka_repack,
                kb_repack, KLoopType::Main);

        jmpi(1 | state.flagAP, lKLoopBegin);

        // Handle barrier if needed.
        if (strategy.barrierFreq > 0) {
            status << "Barrier on k loop" << status_stream::endl;

            GRF temp = state.ra.alloc();
            Subregister newLoops = state.ra.alloc_sub<int32_t>();

            min_(1, newLoops, outerK, int32_t(strategy.barrierFreq));

            barriersignal(temp, r0_info);

            add(1 | gt | state.flagAP, state.K, state.K, newLoops);
            add(1 | sat, outerK.ud(), outerK.ud(),
                    int16_t(-strategy.barrierFreq));

            barrierwait();

            jmpi(1 | state.flagAP, lKLoopBegin);

            state.ra.safeRelease(temp);
            state.ra.safeRelease(newLoops);
        }
    }

    // Cooldown loop(s).
    if (needCooldown) mark(lKLoopCooldown);

    switch (strategy.slmBuffers) {
        case 0:
            if (A_copies > 1 || B_copies > 1) {
                kLoopBody(state.A_layout, state.B_layout, state.A_addrs,
                        state.B_addrs, unrollK, strategy.ka_load,
                        strategy.kb_load, ka_repack, kb_repack,
                        KLoopType::Cooldown);
            }
            break;
        case 1:
            kLoopBody(state.A_layout, state.B_layout, state.A_addrs,
                    state.B_addrs, unrollK, strategy.ka_load, strategy.kb_load,
                    ka_repack, kb_repack, KLoopType::Cooldown);
            break;
        case 2: {
            kLoopBody(state.A_layout, state.B_layout, state.A_addrs,
                    state.B_addrs, unrollK, strategy.ka_load, strategy.kb_load,
                    ka_repack, kb_repack, KLoopType::Cooldown);

            auto temp = state.ra.alloc();

            Label skipFence;
            if (hw >= HW::Gen11) jmpi(1, skipFence);

            mark(lKLoopCooldown1);
            if (hw >= HW::Gen11) {
                slmfence(temp, r0_info);
                if (hw < HW::Xe_LP) mov<uint32_t>(8, null, temp);
                mark(skipFence);
            }

            barrier(temp, r0_info);
            state.ra.safeRelease(temp);

            kLoopBody(state.A_layout, state.B_layout, state.A_addrs,
                    state.B_addrs, unrollK, strategy.ka_load, strategy.kb_load,
                    ka_repack, kb_repack, KLoopType::Cooldown);
            break;
        }
        default: stub();
    }

    mark(lKLoopEnd);

    // k remainder loop. This is performed with unroll = kernel crosspack, A/B_copies = 1
    bool kRemLoop = (unrollK > 1 && remainderK);

    if (kRemLoop) {
        status << "k remainder loop" << status_stream::endl;

        // Collapse A/B copies.
        A_copies = B_copies = slmCopies = 1;
        A_copy = B_copy = 0;

        // By default choose minimum reasonable unroll for the remainder loop.
        int unrollKRem = opCount;

        // Undo offseting on the k loop counter and check for zero remainder loops.
        add(1 | le | state.flagAP, state.K, state.K, uint16_t(unrollK - 1));

        // Fragment the A, B layouts, taking the first column of A and first row of B. Crosspacked columns/rows come together.
        vector<RegisterBlock> A_layout1, B_layout1;
        vector<GRFRange> A_addrs1, B_addrs1;
        int ka_loadRem = problem.A.crosspack, kb_loadRem = problem.B.crosspack;

        if (!getSubblocks(Ta, A_layout1, A_addrs1, state.A_layout,
                    state.A_addrs, true, 0, ka_loadRem, problem.A.padded,
                    problem.A, strategy.A))
            return false;
        if (!getSubblocks(Tb, B_layout1, B_addrs1, state.B_layout,
                    state.B_addrs, false, 0, kb_loadRem, problem.B.padded,
                    problem.B, strategy.B))
            return false;

        // Adjust A/B/Ai/Bi addresses if needed.
        adjustSubblockAddrs(Ta, A_layout1, A_addrs1, state.A_layout,
                state.A_addrs, problem.A, strategy.A, strategy, state);
        adjustSubblockAddrs(Tb, B_layout1, B_addrs1, state.B_layout,
                state.B_addrs, problem.B, strategy.B, strategy, state);

        if (strategy.slmA && !state.A_slmSplitM) {
            vector<RegisterBlock> tempLayout;
            vector<GRFRange> tempAddrs;
            if (!getSubblocks(Ta, tempLayout, tempAddrs, state.Ai_layout,
                        state.Ai_addrs, true, 0, 1, state.Ai.padded, state.Ai,
                        state.Ai_strategy))
                return false;
            adjustSubblockAddrs(Ta, tempLayout, tempAddrs, state.Ai_layout,
                    state.Ai_addrs, state.Ai, state.Ai_strategy, strategy,
                    state);
        }
        if (strategy.slmB && !state.B_slmSplitN) {
            vector<RegisterBlock> tempLayout;
            vector<GRFRange> tempAddrs;
            if (!getSubblocks(Tb, tempLayout, tempAddrs, state.Bi_layout,
                        state.Bi_addrs, false, 0, 1, state.Bi.padded, state.Bi,
                        state.Bi_strategy))
                return false;
            adjustSubblockAddrs(Tb, tempLayout, tempAddrs, state.Bi_layout,
                    state.Bi_addrs, state.Bi, state.Bi_strategy, strategy,
                    state);
        }

        // Adjust A and B pointers as necessary for backward GEMMs.
        int incA = 0, incB = 0;
        Subregister incASub, incBSub;
        if (problem.backward) {
            incA = (strategy.ka_load - ka_loadRem);
            incB = (strategy.kb_load - kb_loadRem);
        }
        if (incA != 0 && !strategy.A.address2D) switch (problem.A.layout) {
                case MatrixLayout::Pc:
                    incA *= strategy.unroll[LoopM] * Ta;
                    break;
                case MatrixLayout::T: incA *= Ta.size(); break;
                case MatrixLayout::N:
                    incASub = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, incASub, state.inputs.lda, std::abs(incA));
                    if (incA < 0) incASub = -incASub;
                    break;
                default: stub();
            }
        if (incB != 0 && !strategy.B.address2D) switch (problem.B.layout) {
                case MatrixLayout::Pr:
                    incB *= strategy.unroll[LoopN] * Tb;
                    break;
                case MatrixLayout::N: incB *= Tb.size(); break;
                case MatrixLayout::T:
                    incBSub = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, incBSub, state.inputs.ldb, std::abs(incB));
                    if (incB < 0) incBSub = -incBSub;
                    break;
                default: stub();
            }
        if (incASub.isValid())
            incAddr(A_addrs1, incASub, 0, incA, A_layout1, problem.A,
                    strategy.A, strategy, state);
        else if (incA)
            incAddr(A_addrs1, incA, 0, incA, A_layout1, problem.A, strategy.A,
                    strategy, state);
        if (incBSub.isValid())
            incAddr(B_addrs1, incBSub, incB, 0, B_layout1, problem.B,
                    strategy.B, strategy, state);
        else if (incB)
            incAddr(B_addrs1, incB, incB, 0, B_layout1, problem.B, strategy.B,
                    strategy, state);

        state.ra.safeRelease(incASub);
        state.ra.safeRelease(incBSub);

        // Recalculate lda_ka/ldb_kb if needed.
        gemmCalcIncrements(problem, strategy, state, ka_loadRem, kb_loadRem);

        // Skip remainder loop if no remainder.
        jmpi(1 | state.flagAP, lKRemLoopEnd);

        // Allocate repack registers if we need to assemble multiple loads for
        //  each outer product calculation.
        if (opCount > 1) {
            int crosspackA, crosspackB, tileM_A, tileK_A, tileK_B, tileN_B;
            std::tie(crosspackA, crosspackB)
                    = targetKernelCrosspack(hw, problem, strategy);
            std::tie(tileM_A, tileK_A, tileK_B, tileN_B)
                    = targetKernelTiling(hw, problem, strategy);

            if (!ka_repack && (ka_loadRem < opCount)) {
                ka_repack = opCount;
                makeUnbackedRegLayout(Ta, state.Ar_layout,
                        strategy.unroll[LoopM], ka_repack,
                        isLayoutColMajor(state.A_layout), crosspackA, tileM_A,
                        tileK_A);
                state.Ar_regs
                        = state.ra.alloc_range(getRegCount(state.Ar_layout),
                                getHint(HintType::A0, strategy));
            }
            if (!kb_repack && (kb_loadRem < opCount)) {
                kb_repack = opCount;
                makeUnbackedRegLayout(Tb, state.Br_layout, kb_repack,
                        strategy.unroll[LoopN],
                        isLayoutColMajor(state.B_layout), crosspackB, tileK_B,
                        tileN_B);
                state.Br_regs
                        = state.ra.alloc_range(getRegCount(state.Br_layout),
                                getHint(HintType::B0, strategy));
            }
        }

        // Extra loop counter for SLM copies, if multiple remainder copies may be needed.
        Subregister kSLM;
        bool needKSLM = (strategy.slmBuffers > 0)
                && (strategy.unroll[LoopK] > strategy.unrollKSLM);
        if (needKSLM) {
            kSLM = state.ra.alloc_sub<uint32_t>();
            mov(1, kSLM, uint16_t(1));
            jmpi(1, lKRemLoopEntry);
        }

        // SLM remainder copy logic.
        bool repacked = false;
        auto remainderCopy = [&]() {
            bool restoreState = false;
            auto savedState = state;
            vector<MaskAssignment> masks;

            // Compute k offsets.
            bool blockSLMA = strategy.slmA && !state.A_slmSplitM;
            bool blockSLMB = strategy.slmB && !state.B_slmSplitN;
            if (blockSLMA || blockSLMB)
                state.hab0Storage = state.ra.alloc_sub<uint32_t>();

            if (blockSLMA) {
                state.ha0_slm = state.hab0Storage.uw(0);
                mulConstant(1, state.ha0_slm, state.lidN, state.ka_slm);
            }
            if (blockSLMB) {
                state.hb0_slm = state.hab0Storage.uw(1);
                mulConstant(1, state.hb0_slm, state.lidM, state.kb_slm);
            }
            if (problem.backward) {
                if (blockSLMA)
                    add(1, state.ha0_slm, -state.ha0_slm,
                            strategy.unrollKSLM - state.ka_slm);
                if (blockSLMB)
                    add(1, state.hb0_slm, -state.hb0_slm,
                            strategy.unrollKSLM - state.kb_slm);
            }

            // Start using k masks.
            if (state.A_slmSplitM || state.B_slmSplitN) {
                Subregister rems[3] = {state.remainders[LoopM],
                        state.remainders[LoopN], state.K};
                auto start = masks.size();

                if (state.A_slmSplitM) {
                    addMasking(state.Ai_layout, false, true, state.Ai,
                            state.Ai_strategy);
                    if (!assignMasks(
                                state.Ai_layout, LoopM, LoopK, masks, state))
                        return false;
                }
                if (state.B_slmSplitN) {
                    addMasking(state.Bi_layout, true, false, state.Bi,
                            state.Bi_strategy);
                    if (!assignMasks(
                                state.Bi_layout, LoopK, LoopN, masks, state))
                        return false;
                }

                if (problem.backward)
                    for (auto m = start; m < masks.size(); m++)
                        masks[m].reverse(strategy.unrollKSLM);

                loadMasks(masks, rems, state, int(start));
                restoreState = true;
            }

            // SLM loads. Try to avoid repacking data if possible.
            bool success = false;

            if (!repacked
                    && ((strategy.slmA && state.aioShare)
                            || (strategy.slmB && state.bioShare))) {
                pushStream();
                success = doRemainderSLMLoads(false);
                success ? appendCurrentStream() : discardStream();
            }
            if (!success) {
                restoreState = true;
                gemmAllocAoBoRegs(true, strategy, state);
                if (!doRemainderSLMLoads(true)) {
                    state = savedState;
                    return false;
                }
                repacked = true;
            }

            state.ra.safeRelease(state.hab0Storage);
            state.ha0_slm = state.hb0_slm = invalid;

            bool remaskA = (opCount > 1)
                    && needsRemask(
                            Ta, true, state.Ai_layout, state.Ai_strategy);
            bool remaskB = (opCount > 1)
                    && needsRemask(
                            Tb, false, state.Bi_layout, state.Bi_strategy);
            if (remaskA || remaskB) {
                // Sub-dword types may not be fully masked (only dword masked).
                // Apply mask by hand.
                if (remaskA && remaskB && Ta.size() != Tb.size()) stub();
                if (problem.backward) stub();

                releaseMaskAssignments(masks, state);
                setupTeardownRemask(remaskA ? Ta : Tb, true,
                        strategy.unrollKSLM, state.K, strategy, state);
                if (remaskA) {
                    auto A_regs = (state.aioShare && !repacked)
                            ? state.Ai_regs[slmCopyStore]
                            : state.Ao_regs;
                    remaskLayout(
                            Ta, true, state.Ao_layout, A_regs, strategy, state);
                }
                if (remaskB) {
                    auto B_regs = (state.bioShare && !repacked)
                            ? state.Bi_regs[slmCopyStore]
                            : state.Bo_regs;
                    remaskLayout(Tb, false, state.Bo_layout, B_regs, strategy,
                            state);
                }
                setupTeardownRemask(remaskA ? Ta : Tb, false,
                        strategy.unrollKSLM, state.K, strategy, state);
            }

            auto temp = state.ra.alloc();
            barrier(temp, r0_info); // TODO: split this barrier around loads.

            doSLMStores(repacked);

            slmBarrier(temp, r0_info);
            state.ra.safeRelease(temp);

            if (restoreState) state = savedState;

            return true;
        };

        // For SLM copies, do remainder copy every unrollKSLM loops.
        if (strategy.slmBuffers > 0) {
            if (kSLM.isValid()) {
                // Start remainder loop.
                mark(lKRemLoopBegin);
                if (!is_zero_or_pow2(strategy.unrollKSLM)) stub();
                and_(1 | nz | state.flagAP, null.ud(), kSLM,
                        uint16_t(strategy.unrollKSLM - 1));
                add(1, kSLM, kSLM, uint16_t(1));
                jmpi(1 | state.flagAP, lKRemLoopNoSLMLoad);

                // Reset SLM pointers when reloading.
                if (strategy.slmA)
                    doAIncrement(A_layout1, A_addrs1, problem.A, strategy.A,
                            -strategy.unrollKSLM * strategy.slmBuffers, problem,
                            strategy, state);
                if (strategy.slmB)
                    doBIncrement(B_layout1, B_addrs1, problem.B, strategy.B,
                            -strategy.unrollKSLM * strategy.slmBuffers, problem,
                            strategy, state);
                mark(lKRemLoopEntry);
            }

            if (!remainderCopy()) return false;
        }

        // Main remainder loop.
        mark(kSLM.isValid() ? lKRemLoopNoSLMLoad : lKRemLoopBegin);
        bool checkRem = ((opCount > 1) && (ka_repack || kb_repack))
                || (unrollKRem > opCount);
        lateKLoopCheck |= checkRem;
        kLoopBody(A_layout1, B_layout1, A_addrs1, B_addrs1, unrollKRem,
                ka_loadRem, kb_loadRem, std::min(unrollKRem, ka_repack),
                std::min(unrollKRem, kb_repack), KLoopType::Remainder,
                checkRem);
        jmpi(1 | state.flagAP, lKRemLoopBegin);

        mark(lKRemLoopEnd);

        // Clean up temporaries.
        if (!ka_repack_in && !state.Ar_layout.empty()) {
            state.Ar_layout.clear();
            safeReleaseRanges(state.Ar_regs, state);
            ka_repack = ka_repack_in;
        }
        if (!kb_repack_in && !state.Br_layout.empty()) {
            state.Br_layout.clear();
            safeReleaseRanges(state.Br_regs, state);
            kb_repack = kb_repack_in;
        }
        state.ra.safeRelease(kSLM);
    }

    state.ra.safeRelease(slmIncLoadStorage);
    state.ra.safeRelease(slmIncStoreStorage);

    return true;
}

// Perform the body of the GEMM computation, updating a block of C.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmAccumulateC(
        GEMMProblem problem, GEMMStrategy &strategy, GEMMState &state) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc,
         Tc_ext = problem.Tc_ext;
    bool lateKLoopCheck = false;
    bool cLoadAhead = strategy.cLoadAhead;

    // Decide what remainder handling needs to be done.
    bool remainderM = strategy.remHandling[LoopM] != RemainderHandling::Ignore;
    bool remainderN = strategy.remHandling[LoopN] != RemainderHandling::Ignore;
    bool remainderK = strategy.remHandling[LoopK] != RemainderHandling::Ignore;
    bool remM_A = remainderM && !problem.A.padded;
    bool remK_A = false;
    bool remK_B = false;
    bool remN_B = remainderN && !problem.B.padded;
    bool remM_C = remainderM && !problem.C.padded && !strategy.altCRemainder;
    bool remN_C = remainderN && !problem.C.padded && !strategy.altCRemainder;
    bool remM_Ce = remM_C;
    bool remN_Ce = remN_C;

    if (state.copyC) remM_C = remN_C = false;

    // Get register layouts for SLM copies and adjust problem.
    if (strategy.slmBuffers > 0) {
        int A_slmCP, B_slmCP;
        int A_tileR, A_tileC, B_tileR, B_tileC;
        std::tie(A_slmCP, B_slmCP) = targetSLMCrosspack(hw, problem, strategy);
        std::tie(A_tileR, A_tileC, B_tileR, B_tileC)
                = targetKernelTiling(hw, problem, strategy);

        if (strategy.slmA) {
            // Decide how to split up A block between threads. Don't split in m dimension with remainders.
            state.A_slmSplitM = maySLMSplitM(problem, strategy);
            if (state.A_slmSplitM && remM_A) {
                strategy.A.accessType = isColMajor(problem.A.layout)
                        ? AccessType::Block
                        : AccessType::Scattered;
                state.A_slmSplitM = false;
            }
            if (state.A_slmSplitM) {
                if (strategy.unroll[LoopM] % strategy.wg[LoopN]) stub();
                state.ma_slm = strategy.unroll[LoopM] / strategy.wg[LoopN];
                state.ka_slm = strategy.unrollKSLM;
                remM_A = false;
                remK_A = remainderK;
            } else {
                if (strategy.unrollKSLM % strategy.wg[LoopN]) stub();
                state.ma_slm = strategy.unroll[LoopM];
                state.ka_slm = strategy.unrollKSLM / strategy.wg[LoopN];
            }
            bool splitCP = (state.ka_slm < A_slmCP);
            if (splitCP && (strategy.unrollKSLM != A_slmCP))
                throw std::runtime_error(
                        "ka_slm must be a multiple of crosspack, or unrollKSLM "
                        "= crosspack.");

            // Layout in from memory...
            state.Ai = problem.A;
            state.Ai_strategy = strategy.A;

            // ... layout out to SLM.
            state.Ao.base = SLM;
            state.Ao.layout = MatrixLayout::Pc;
            state.Ao.packSize = strategy.unroll[LoopM];
            state.Ao.padded = true;
            state.Ao.crosspack = A_slmCP;
            state.Ao.setAlignment(state.Ao.packSize * Ta);
            state.Ao.tileR = A_tileR;
            state.Ao.tileC
                    = (A_tileC || !A_tileR) ? A_tileC : strategy.unrollKSLM;

            state.Ao_strategy.accessType
                    = (!state.A_slmSplitM || strategy.slmMBlockSplit)
                    ? AccessType::Block
                    : AccessType::Scattered;
            state.Ao_strategy.atomic = false;

            // Layout in from memory...
            if (!getRegLayout(Ta, state.Ai_layout, state.ma_slm, state.ka_slm,
                        remM_A, remK_A, false, true, ScatterSIMD::Default, 0, 0,
                        state.Ai, state.Ai_strategy))
                return false;

            // ... layout out to SLM...
            remM_A = remK_A = false;
            if (!getRegLayout(Ta, state.Ao_layout, state.ma_slm, state.ka_slm,
                        remM_A, remK_A, true, true, ScatterSIMD::Default, 0, 0,
                        state.Ao, state.Ao_strategy))
                return false;

            // ... and layout back from SLM.
            problem.A = state.Ao;
            strategy.A.accessType = AccessType::Block;

            state.aioShare = matchLayouts(Ta, state.Ai_layout, state.Ao_layout);

            // Offset A addresses in and out.
            state.effAi = state.effA;
            state.effA
                    = state.ra.alloc_sub<uint32_t>(getHint(HintType::LongTerm));
            state.effAo
                    = state.ra.alloc_sub<uint32_t>(getHint(HintType::LongTerm));

            auto temp = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));
            auto temp2 = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));

            int32_t noff;
            if (state.A_slmSplitM)
                noff = strategy.slmMBlockSplit
                        ? state.ma_slm * state.ka_slm
                        : state.ma_slm * state.Ao.crosspack;
            else
                noff = state.ka_slm
                        * (splitCP ? 1 : A_tileR ? A_tileR : state.Ao.packSize);

            gemmCalcAiOffset(temp2, problem, strategy, state);
            mulConstant(1, temp, state.lidN, noff * Ta);
            mulConstant(1, state.effA, state.lidM,
                    strategy.slmABufBlockSize(Ta, state) * strategy.slmBuffers);
            eadd(1, state.effAi, state.effAi, temp2, strategy, state);
            add(1, state.effAo, state.effA, temp);
            if (problem.backward)
                add(1, state.effA, state.effA,
                        (strategy.unrollKSLM - strategy.ka_load)
                                * strategy.unroll[LoopM] * Ta);

            state.ra.safeRelease(temp2);
            state.ra.safeRelease(temp);
        }
        if (strategy.slmB) {
            // Decide how to split up B block between threads.
            state.B_slmSplitN = maySLMSplitN(problem, strategy);
            if (state.B_slmSplitN && remN_B) {
                strategy.B.accessType = !isColMajor(problem.B.layout)
                        ? AccessType::Block
                        : AccessType::Scattered;
                state.B_slmSplitN = false;
            }
            if (state.B_slmSplitN) {
                if (strategy.unroll[LoopN] % strategy.wg[LoopM]) stub();
                state.kb_slm = strategy.unrollKSLM;
                state.nb_slm = strategy.unroll[LoopN] / strategy.wg[LoopM];
                remN_B = false;
                remK_B = remainderK;
            } else {
                if (strategy.unrollKSLM % strategy.wg[LoopM]) stub();
                state.kb_slm = strategy.unrollKSLM / strategy.wg[LoopM];
                state.nb_slm = strategy.unroll[LoopN];
            }
            bool splitCP = (state.kb_slm < B_slmCP);
            if (splitCP && (strategy.unrollKSLM != B_slmCP))
                throw std::runtime_error(
                        "kb_slm must be a multiple of crosspack, or unrollKSLM "
                        "= crosspack.");

            // Layout in from memory...
            state.Bi = problem.B;
            state.Bi_strategy = strategy.B;

            // ... layout out to SLM.
            state.Bo.base = SLM;
            state.Bo.layout = MatrixLayout::Pr;
            state.Bo.packSize = strategy.unroll[LoopN];
            state.Bo.padded = true;
            state.Bo.crosspack = B_slmCP;
            state.Bo.setAlignment(state.Bo.packSize * Tb);
            state.Bo.tileR
                    = (B_tileR || !B_tileC) ? B_tileR : strategy.unrollKSLM;
            state.Bo.tileC = B_tileC;

            state.Bo_strategy.accessType
                    = (!state.B_slmSplitN || strategy.slmNBlockSplit)
                    ? AccessType::Block
                    : AccessType::Scattered;
            state.Bo_strategy.atomic = false;

            // Layout in from memory...
            if (!getRegLayout(Tb, state.Bi_layout, state.kb_slm, state.nb_slm,
                        remK_B, remN_B, false, true, ScatterSIMD::Default, 0, 0,
                        state.Bi, state.Bi_strategy))
                return false;

            // ... layout out to SLM...
            remK_B = remN_B = false;
            if (!getRegLayout(Tb, state.Bo_layout, state.kb_slm, state.nb_slm,
                        remK_B, remN_B, true, true, ScatterSIMD::Default, 0, 0,
                        state.Bo, state.Bo_strategy))
                return false;

            // ... and layout back from SLM.
            problem.B = state.Bo;
            strategy.B.accessType = AccessType::Block;

            state.bioShare = matchLayouts(Tb, state.Bi_layout, state.Bo_layout);

            // Offset B addresses in and out.
            state.effBi = state.effB;
            state.effB
                    = state.ra.alloc_sub<uint32_t>(getHint(HintType::LongTerm));
            state.effBo
                    = state.ra.alloc_sub<uint32_t>(getHint(HintType::LongTerm));

            auto temp = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));
            auto temp2 = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));

            int32_t moff;
            if (state.B_slmSplitN)
                moff = strategy.slmNBlockSplit
                        ? state.nb_slm * state.kb_slm
                        : state.nb_slm * state.Bo.crosspack;
            else
                moff = state.kb_slm * (splitCP ? 1 : state.Bo.packSize);

            gemmCalcBiOffset(temp2, problem, strategy, state);
            mulConstant(1, temp, state.lidM, moff * Tb);
            mulConstant(1, state.effB, state.lidN,
                    strategy.slmBBufBlockSize(Tb, state) * strategy.slmBuffers);
            eadd(1, state.effBi, state.effBi, temp2, strategy, state);
            if (strategy.slmABufSize(Ta, state) > 0)
                add(1, state.effB, state.effB, strategy.slmABufSize(Ta, state));
            add(1, state.effBo, state.effB, temp);
            if (problem.backward)
                add(1, state.effB, state.effB,
                        (strategy.unrollKSLM - strategy.kb_load)
                                * strategy.unroll[LoopN] * Tb);

            state.ra.safeRelease(temp2);
            state.ra.safeRelease(temp);
        }

        if (!(remainderK || (problem.abOffset == ABOffset::Calc)))
            releaseSavedLocalIDs(state);
    }

    // Get register layouts for A/B/C.
    auto simdModeC = strategy.forceWideSIMDC ? ScatterSIMD::Wide
                                             : ScatterSIMD::Default;
    if (!getRegLayout(Ta, state.A_layout, strategy.unroll[LoopM],
                strategy.ka_load, remM_A, remK_A, false, true,
                ScatterSIMD::Default, 0, 0, problem.A, strategy.A))
        return false;
    if (!getRegLayout(Tb, state.B_layout, strategy.kb_load,
                strategy.unroll[LoopN], remK_B, remN_B, false, true,
                ScatterSIMD::Default, 0, 0, problem.B, strategy.B))
        return false;
    if (!getRegLayout(Tc, state.C_layout, strategy.unroll[LoopM],
                strategy.unroll[LoopN], remM_C, remN_C, true, false, simdModeC,
                0, 0, problem.C, strategy.C))
        return false;

    if (state.copyC) {
        if (!getRegLayout(Tc_ext, state.C_layoutExt, strategy.unroll[LoopM],
                    strategy.unroll[LoopN], remM_Ce, remN_Ce, true, false,
                    simdModeC, 0, 0, problem.C, strategy.C))
            return false;
    } else
        state.C_layoutExt = state.C_layout;

    if (hasRowFragmenting(state.A_layout)
            || hasColumnFragmenting(state.B_layout)) {
        status << "Can't fragment A or B.\n";
        return false;
    }

    // Handle repacking. Repacking can be requested in strategy, or it will enabled here if necessary.
    auto ka_repack = strategy.ka_repack;
    auto kb_repack = strategy.kb_repack;

    int crosspackA, crosspackB, tileM_A, tileK_A, tileK_B, tileN_B;
    std::tie(crosspackA, crosspackB)
            = targetKernelCrosspack(hw, problem, strategy);
    std::tie(tileM_A, tileK_A, tileK_B, tileN_B)
            = targetKernelTiling(hw, problem, strategy);

    bool mustRepackA
            = (crosspackA && !hasFullCrosspack(state.A_layout, crosspackA))
            || !hasTiling(state.A_layout, tileM_A, tileK_A);
    bool mustRepackB
            = (crosspackB && !hasFullCrosspack(state.B_layout, crosspackB))
            || !hasTiling(state.B_layout, tileK_B, tileN_B);

    if (!ka_repack && mustRepackA) ka_repack = strategy.ka_load;
    if (!kb_repack && mustRepackB) kb_repack = strategy.kb_load;

    if (ka_repack)
        makeUnbackedRegLayout(Ta, state.Ar_layout, strategy.unroll[LoopM],
                ka_repack, isLayoutColMajor(state.A_layout), crosspackA,
                tileM_A, tileK_A);
    if (kb_repack)
        makeUnbackedRegLayout(Tb, state.Br_layout, kb_repack,
                strategy.unroll[LoopN], isLayoutColMajor(state.B_layout),
                crosspackB, tileK_B, tileN_B);

    // Prepare layouts for row/column sum calculation.
    if (problem.abOffset == ABOffset::Calc) {
        auto As_srcLayout = strategy.slmA
                ? state.Ao_layout
                : ka_repack ? state.Ar_layout : state.A_layout;
        auto Bs_srcLayout = strategy.slmB
                ? state.Bo_layout
                : kb_repack ? state.Br_layout : state.B_layout;
        makeSumLayout(
                false, Ta, As_srcLayout, Tc, state.As_layout, strategy, state);
        makeSumLayout(
                true, Tb, Bs_srcLayout, Tc, state.Bs_layout, strategy, state);
    }

    // Round up needed A/B flag registers; hold off on C.
    // Try first without virtual flags and retry if needed.
    // SLM scattered stores use k masking, so skip those masks for now.
    vector<MaskAssignment> masks;

    bool success = assignMasks(state.A_layout, LoopM, LoopK, masks, state)
            && assignMasks(state.B_layout, LoopK, LoopN, masks, state)
            && (state.A_slmSplitM
                    || assignMasks(state.Ai_layout, LoopM, LoopK, masks, state))
            && (state.B_slmSplitN
                    || assignMasks(
                            state.Bi_layout, LoopK, LoopN, masks, state));

    if (!success && state.vflagStorage.isInvalid()) {
        status << "Retrying with virtual flags." << status_stream::endl;
        allocVFlagStorage(strategy, state);
        success = assignMasks(state.A_layout, LoopM, LoopK, masks, state)
                && assignMasks(state.B_layout, LoopK, LoopN, masks, state)
                && (state.A_slmSplitM
                        || assignMasks(
                                state.Ai_layout, LoopM, LoopK, masks, state))
                && (state.B_slmSplitN
                        || assignMasks(
                                state.Bi_layout, LoopK, LoopN, masks, state));

        lateKLoopCheck = true;
    }

    if (!success) return false;

    loadMasks(masks, state.remainders, state);

    // Temporary: move add64 out of the way (later: general cramming).
    if (state.add64.isValid()) {
        auto oldAdd64 = state.add64;
        state.ra.safeRelease(state.add64);
        state.add64 = state.ra.alloc_sub<uint32_t>();
        if (oldAdd64 != state.add64) mov(1, state.add64, oldAdd64);
    }

    // Allocate data registers.
    gemmAllocRegs(problem, strategy, state);
    gemmAllocAoBoRegs(false, strategy, state);

    // Allocate address registers for A/B loads. We don't need C addresses yet.
    allocAddrRegs(state.A_addrs, state.A_layout, problem.A, strategy.A, state);
    allocAddrRegs(state.B_addrs, state.B_layout, problem.B, strategy.B, state);
    allocAddrRegs(state.Ai_addrs, state.Ai_layout, state.Ai, state.Ai_strategy,
            state);
    allocAddrRegs(state.Bi_addrs, state.Bi_layout, state.Bi, state.Bi_strategy,
            state);
    allocAddrRegs(state.Ao_addrs, state.Ao_layout, state.Ao, state.Ao_strategy,
            state);
    allocAddrRegs(state.Bo_addrs, state.Bo_layout, state.Bo, state.Bo_strategy,
            state);

    // Set up address registers.
    Address2DParams A_params, B_params;
    A_params.rows = state.inputs.m;
    A_params.cols = state.inputs.k;
    A_params.offR = state.i0;
    A_params.offC = state.h0;
    A_params.remR = state.remainders[LoopM];
    B_params.rows = state.inputs.k;
    B_params.cols = state.inputs.n;
    B_params.offR = state.h0;
    B_params.offC = state.j0;
    B_params.remC = state.remainders[LoopN];
    setupAddr(Ta, state.Ai_addrs, state.effAi, state.Ai_layout,
            state.inputs.lda, state.Ai, state.Ai_strategy, strategy, state,
            A_params);
    setupAddr(Tb, state.Bi_addrs, state.effBi, state.Bi_layout,
            state.inputs.ldb, state.Bi, state.Bi_strategy, strategy, state,
            B_params);
    setupAddr(Ta, state.Ao_addrs, state.effAo, state.Ao_layout, Subregister(),
            state.Ao, state.Ao_strategy, strategy, state);
    setupAddr(Tb, state.Bo_addrs, state.effBo, state.Bo_layout, Subregister(),
            state.Bo, state.Bo_strategy, strategy, state);
    setupAddr(Ta, state.A_addrs, state.effA, state.A_layout, state.inputs.lda,
            problem.A, strategy.A, strategy, state, A_params);
    setupAddr(Tb, state.B_addrs, state.effB, state.B_layout, state.inputs.ldb,
            problem.B, strategy.B, strategy, state, B_params);

    // Free unneeded registers after address setup.
    if (!state.isNested) {
        state.ra.safeRelease(state.h0);
        if (strategy.A.address2D) state.ra.safeRelease(state.inputs.lda);
        if (strategy.B.address2D) state.ra.safeRelease(state.inputs.ldb);
        if (!strategy.C.address2D) {
            state.ra.safeRelease(state.i0);
            state.ra.safeRelease(state.j0);
        }
    }

    // Load C now if configured.
    //  - temporarily free A/B data regs to use as C headers
    //  - do beta scaling
    if (cLoadAhead) {
        if (problem.checkBeta0 && !problem.beta_real.fixed()) stub();
        if (state.C_accCount > 0) stub();

        releaseRanges(state.A_regs, state);
        releaseRanges(state.B_regs, state);
        if (!state.Ar_regs.empty()) releaseRanges(state.Ar_regs, state);
        if (!state.Br_regs.empty()) releaseRanges(state.Br_regs, state);

        status << "Loading C" << status_stream::endl;
        gemmAccessC(COperation::Load, problem, strategy, state);

        gemmBetaScale(problem, strategy, state);
        if (!state.Br_regs.empty()) reclaimRanges(state.Br_regs, state);
        if (!state.Ar_regs.empty()) reclaimRanges(state.Ar_regs, state);
        reclaimRanges(state.B_regs, state);
        reclaimRanges(state.A_regs, state);
    }

    // Release 64-bit emulation registers as they aren't needed in the inner loop.
    // Could also move r0 to acc here.
    GRF emulate64Temp[2];
    if (state.emulate.temp[0].isValid()) {
        for (int q = 0; q < 2; q++) {
            emulate64Temp[q] = state.emulate.temp[q];
            state.ra.safeRelease(state.emulate.temp[q]);
        }
        state.emulate.flag = state.flagAP;
        state.emulate.flagOffset = 8;
        lateKLoopCheck = false;
    }

    // Synthesize k loop. If configured, choose between 32-bit adds and 64-bit adds.
    if (strategy.checkAdd32 && state.add64.isValid()) {
        Label loop64, done;
        bool success = true;

        cmp(1 | ne | state.flagAP, state.add64, uint16_t(0));
        jmpi(1 | state.flagAP, loop64);
        state.ra.safeRelease(state.add64);

        status << "k loop: 32-bit address update" << status_stream::endl;
        strategy.emulate.emulate64_add32 = true;
        success &= gemmKLoop(
                ka_repack, kb_repack, lateKLoopCheck, problem, strategy, state);
        jmpi(1, done);

        mark(loop64);
        status << "k loop: 64-bit address update" << status_stream::endl;
        strategy.emulate.emulate64_add32 = false;
        success &= gemmKLoop(
                ka_repack, kb_repack, lateKLoopCheck, problem, strategy, state);

        mark(done);
        if (!success) return false;
    } else {
        state.ra.safeRelease(state.add64);
        if (!gemmKLoop(ka_repack, kb_repack, lateKLoopCheck, problem, strategy,
                    state))
            return false;
    }

    // Restore emulation registers.
    if (emulate64Temp[0].isValid()) {
        for (int q = 0; q < 2; q++) {
            state.emulate.temp[q] = emulate64Temp[q];
            if (emulate64Temp[q].isValid()) state.ra.claim(emulate64Temp[q]);
        }
        state.emulate.flag = invalid;
        state.emulate.flagOffset = 0;
    }

    // We're done with A and B. Free their address, data, and flag registers.
    // Also done with loop counter.
    releaseMaskAssignments(masks, state);
    safeReleaseRanges(state.A_addrs, state);
    safeReleaseRanges(state.B_addrs, state);
    safeReleaseRanges(state.Ai_addrs, state);
    safeReleaseRanges(state.Bi_addrs, state);
    safeReleaseRanges(state.Ao_addrs, state);
    safeReleaseRanges(state.Bo_addrs, state);

    safeReleaseRanges(state.A_regs, state);
    safeReleaseRanges(state.A1_regs, state);
    safeReleaseRanges(state.Ar_regs, state);
    safeReleaseRanges(state.Ai_regs, state);
    safeReleaseRanges(state.Ao_regs, state);
    safeReleaseRanges(state.B_regs, state);
    safeReleaseRanges(state.B1_regs, state);
    safeReleaseRanges(state.Br_regs, state);
    safeReleaseRanges(state.Bi_regs, state);
    safeReleaseRanges(state.Bo_regs, state);
    state.ra.safeRelease(state.broadcast_regs);
    safeReleaseRanges(state.tempMul_regs, state);

    state.A_layout.clear();
    state.B_layout.clear();
    state.Ai_layout.clear();
    state.Bi_layout.clear();
    state.Ao_layout.clear();
    state.Bo_layout.clear();
    state.Ar_layout.clear();
    state.Br_layout.clear();

    if (lateKLoopCheck) state.raVFlag.lock(state.flagAP);

    // Restore A/B addresses that were modified by SLM copies.
    if (strategy.slmA) {
        state.ra.safeRelease(state.effA);
        state.ra.safeRelease(state.effAo);
        state.effA = state.effAi;
        state.effAi = invalid;
    }
    if (strategy.slmB) {
        state.ra.safeRelease(state.effB);
        state.ra.safeRelease(state.effBo);
        state.effB = state.effBi;
        state.effBi = invalid;
    }

    // Put accumulators with the rest of C.
    if (state.C_accCount > 0) {
        // Reclaim the bottom registers of C.
        reclaimRanges(state.C_regs[0], state);

        auto e = elementsPerGRF<uint32_t>(hw);
        for (int i = 0; i < AccumulatorRegister::count(hw); i += 2)
            mov<uint32_t>(2 * e, state.C_regs[0][i], AccumulatorRegister(i));
    }

    // Add A/B offsets.
    gemmLoadABOffset(problem, strategy, state);
    if (!gemmFinalizeSums(problem, strategy, state)) return false;
    gemmApplyABOffset(problem, strategy, state);

    return true;
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::setupCAddr0(GRFRange (&C_addr0)[2],
        const vector<RegisterBlock> &C_layout, int C_count,
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    // We assume (0, 0) is in block 0 of the layout.
    if (C_layout[0].offsetR != 0 || C_layout[0].offsetC != 0) stub();

    Address2DParams params;
    params.rows = state.inputs.m;
    params.cols = state.inputs.n;
    params.offR = state.i0;
    params.offC = state.j0;
    params.remR = state.remainders[LoopM];
    params.remC = state.remainders[LoopN];
    for (int q = 0; q < C_count; q++) {
        C_addr0[q] = state.ra.alloc_range(
                addrGRFCount(problem.C, strategy.C, C_layout[0]));
        setupAddr(C_addr0[q], state.effC[q], C_layout[0], state.inputs.ldc[q],
                problem.Tc.size(), problem.C, strategy.C, strategy, state,
                params);
    }
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmUpdateC(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {

    auto Ts = problem.Ts;

    status << "C update" << status_stream::endl;

    auto &alphar = problem.alpha_real;
    auto &betar = problem.beta_real;

    if (strategy.cLoadAhead) {
        betar = 0;
        if (!problem.alpha1()) stub();
    }

    // C early offset.
    if (problem.cOffset == COffset::Pre)
        if (!gemmApplyCOffsetDispatch(problem, strategy, state)) return false;

    // Prepare postop injector if configured.
    GRFRange postOpScratch;
    if (problem.hasPostOp()) {
        postOpInjector.reset(new Injector(this, problem.postOp,
                problem.eltwiseAlpha, problem.eltwiseBeta, problem.eltwiseScale,
                GRFRange(), problem.postOpFwd));
        if (!postOpInjector) stub();

        postOpScratch = state.ra.try_alloc_range(
                postOpInjector->preferred_scratch_regs());
        if (postOpScratch.isInvalid())
            postOpScratch
                    = state.ra.alloc_range(postOpInjector->min_scratch_regs());
        postOpInjector->set_scratch(postOpScratch);
    }

    // Convert C to the type of alpha/beta if needed and if possible (no data size change).
    // If not possible, must be done at a lower level during C update.
    bool successfulConvert = true;

    if (problem.needsTsConvert())
        successfulConvert = gemmConvertC(Ts, problem, strategy, state);

    // Scale by alpha now if alpha and beta are both nontrivial. Todo: move above beta = 0 check,
    //  handle double precision correctly (load alpha to register first).
    // Also scale if atomically updating C.
    bool nontrivialAlpha = !problem.alpha1() && !problem.alphaM1();
    bool scaleForAtomic = !problem.alpha1() && strategy.C.atomic;

    if (successfulConvert
            && ((nontrivialAlpha && (!problem.beta1() || strategy.doubleWA))
                    || scaleForAtomic)) {

        map(hw, Ts.real(), state.C_regs[0], state.C_regs[0], strategy,
                [&](int esize, GRF acc, GRF _) {
                    alphar.fixed()
                            ? mul(esize, acc, acc, cast(Ts.real(), alphar))
                            : mul(esize, acc, acc,
                                    alphar.getRegAvoiding(hw, acc));
                });

        alphar = 1;
    }

    // Do the actual updating.
    if (!gemmAccessC(COperation::UpdateStore, problem, strategy, state))
        return false;

    // Postop cleanup.
    if (problem.hasPostOp()) {
        postOpInjector.reset();
        state.ra.safeRelease(postOpScratch);
    }

    // Free C data and layout.
    safeReleaseRanges(state.C_regs, state);
    state.C_layout.clear();
    state.C_layoutExt.clear();

    // Success!
    return true;
}

// Load from, update, and/or store to C, with complete remainder handling.
// If op == COperation::Load, only load C.
// If op == COperation::Update, load and update C.
// If op == COperation::UpdateStore, perform full C update with alpha/beta scaling. Unless state.isNested == true, assumed
//   to be the conclusion of the kernel.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmAccessC(COperation op,
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    Label labelAltCRemainder, labelAltCRemDone, labelSkip;

    int C_count = (op == COperation::UpdateStore) ? state.C_count : 1;
    bool remainderM
            = (strategy.remHandling[LoopM] != RemainderHandling::Ignore);
    bool remainderN
            = (strategy.remHandling[LoopN] != RemainderHandling::Ignore);
    bool remM_C = remainderM && !problem.C.padded && !strategy.altCRemainder;
    bool remN_C = remainderN && !problem.C.padded && !strategy.altCRemainder;
    bool altCRemainder = strategy.altCRemainder && !problem.C.padded
            && (remainderM || remainderN);
    bool stdCRemainder = !(altCRemainder
            && (strategy.remHandling[LoopM]
                    == RemainderHandling::KnownRemainder)
            && (strategy.remHandling[LoopN]
                    == RemainderHandling::KnownRemainder));

    if ((op != COperation::UpdateStore) && strategy.C.atomic) stub();

    if (state.allowEmptyC && (remainderM || remainderN)) {
        if (!state.isNested) stub();
        int simt = problem.fused ? 16 : 1;
        cmp(simt | le | f0[0], null.ud(), state.remainders[LoopM], 0);
        cmp(simt | le | f1[0], null.ud(), state.remainders[LoopN], 0);
        problem.fused ? goto12(16 | f0[0] | anyv, labelSkip)
                      : ejmpi(1 | f0[0] | anyv, labelSkip);
    }

    if (op == COperation::UpdateStore && problem.cOffset == COffset::Post) {
        // C postoffset is implemented by splitting the update and store steps.
        bool ok = true;

        if (!(problem.alpha1() && problem.beta0()))
            ok = ok
                    && gemmAccessC(
                            COperation::Update, problem, strategy, state);
        auto storeProblem = problem;
        storeProblem.cOffset = COffset::None;
        storeProblem.alpha_real = 1;
        storeProblem.alpha_imag = 0;
        storeProblem.beta_real = 0;
        storeProblem.beta_imag = 0;
        gemmConvertC(problem.Tc, problem, strategy, state);
        ok = ok && gemmApplyCOffsetDispatch(problem, strategy, state);
        ok = ok
                && gemmAccessC(
                        COperation::UpdateStore, storeProblem, strategy, state);
        return ok;
    }

    if (stdCRemainder) {
        // Check to see if we should jump to alternate C remainder handling path, when enabled:
        //  - if this a remainder kernel
        //  - for triangular updates, if the diagonal crosses this block.
        //       When fusing, check diagonal for thread 0 for (fused in n) upper/m lower, thread 1 for n lower/m upper.
        if (altCRemainder) {
            if (remainderM || remainderN) {
                cmp(1 | lt | f0[0], null.ud(), state.remaindersFused[LoopM],
                        strategy.unroll[LoopM]);
                cmp(1 | lt | f1[0], null.ud(), state.remaindersFused[LoopN],
                        strategy.unroll[LoopN]);
            }

            if (remainderM || remainderN)
                ejmpi(1 | f0[0] | anyv, labelAltCRemainder);
        }

        // Unless using SIMT control flow later, we are done with the all-purpose flag. Release it.
        // (Note state is a copy, so flag will be reclaimed when we return.)
        if (!problem.fused && !strategy.noJumpTables)
            state.raVFlag.safeRelease(state.flagAP);

        // Decide on the C remainder handling strategy.
        bool fragments[2] = {false, false};
        bool fragPositives[2] = {true, true};
        int fragSizes[2] = {1 << 16, 1 << 16};

        // Check for fragmenting.
        auto &C_layoutExt = state.C_layoutExt;
        bool remDescs[2] = {false, false};
        bool remMasks[2] = {false, false};

        // Loop over rows (rc = 0) and columns (rc = 1)
        for (int rc = 0; rc < 2; rc++) {
            if (!(rc ? remN_C : remM_C))
                continue; // Skip if not doing remainder handling in this dimension.

            for (auto &l : C_layoutExt) {
                auto qFragment = rc ? l.colFragment : l.rowFragment;
                bool qZeroOK = rc ? l.noColsOK : l.noRowsOK;
                bool qMasked = rc ? (bool)l.colMask : (bool)l.rowMask;
                bool qDescRem = rc ? l.descRemC : l.descRemR;

                if (qFragment > 0) {
                    fragments[rc] = true;
                    fragSizes[rc] = std::min<int>(fragSizes[rc], qFragment);
                    if (qZeroOK) fragPositives[rc] = false;

                    if (qFragment > 1) {
                        remDescs[rc] |= qDescRem;
                        remMasks[rc] |= !qDescRem;
                    }
                } else
                    remMasks[rc] |= qMasked;
            }
        }

        // Disable fragmentation if fragment size is bigger than unroll.
        fragments[0] &= fragSizes[0] < strategy.unroll[LoopM];
        fragments[1] &= fragSizes[1] < strategy.unroll[LoopN];

        // Sanity check the requirements.
        if ((remDescs[0] && remMasks[0]) || (remDescs[1] && remMasks[1])) {
            status << "Different remainder types mixed in C layout."
                   << status_stream::endl;
            return false;
        }
        if (remMasks[0] && remMasks[1]) {
            status << "Both dimensions are masked (not supported)."
                   << status_stream::endl;
            return false;
        }
        if (remDescs[0] && remDescs[1]) {
            status << "Both dimensions use descriptors (not supported)."
                   << status_stream::endl;
            return false;
        }

        // Set remainder handling types.
        StdCRemType remTypes[2] = {StdCRemType::Ignore, StdCRemType::Ignore};
        for (int rc = 0; rc < 2; rc++) {
            if (remDescs[rc])
                remTypes[rc] = StdCRemType::Descriptor;
            else if (remMasks[rc])
                remTypes[rc] = StdCRemType::Mask;
        }

        // Decide whether to do m or n first. Criteria, in order of priority:
        //   - Do a fragmented dimension first.
        //   - Do descriptors first.
        //   - Do whichever dimension of C is strided first.
        bool nFirst;
        if (fragments[0] != fragments[1])
            nFirst = fragments[1];
        else if (remDescs[0] || remDescs[1])
            nFirst = remDescs[1];
        else
            nFirst = (problem.C.layout == MatrixLayout::N);

        // Prepare for load/store descriptor generation.
        if (remDescs[0] || remDescs[1])
            setupTeardownLoadStoreDesc(true, strategy, state);

        // Set up address for the beginning of C.
        GRFRange C_addr0[2];
        setupCAddr0(C_addr0, C_layoutExt, C_count, problem, strategy, state);

        // Try to load C masks. If that fails, fragment the masked dimension down to the size of current blocks.
        vector<MaskAssignment> masks;
        if (!assignMasks(C_layoutExt, LoopM, LoopN, masks, state)) {
            for (int rc = 0; rc < 2; rc++) {
                if (remMasks[rc]) {
                    fragments[rc] = true;
                    fragSizes[rc] = rc ? C_layoutExt[0].nc : C_layoutExt[0].nr;
                }
            }
        } else
            loadMasks(masks, state.remainders, state);

        // Call the remainder handling routine. If it fails, try again, switching M and N.
        // If that still fails, then try again with complete fragmentation if partial
        //  fragmentation attempted the first time.
        bool columns[2] = {nFirst, !nFirst};
        bool switchedColumns[2] = {!nFirst, nFirst};
        do {
            if (doStdCRemainder(C_layoutExt, false, columns, remTypes,
                        fragments, fragPositives, fragSizes, C_addr0, op, masks,
                        problem, strategy, state))
                break;
            if (doStdCRemainder(C_layoutExt, false, switchedColumns, remTypes,
                        fragments, fragPositives, fragSizes, C_addr0, op, masks,
                        problem, strategy, state))
                break;

            if ((fragments[0] && (fragSizes[0] > 1))
                    || (fragments[1] && (fragSizes[1] > 1))) {
                fragSizes[0] = fragSizes[1] = 1;

                if (doStdCRemainder(C_layoutExt, false, columns, remTypes,
                            fragments, fragPositives, fragSizes, C_addr0, op,
                            masks, problem, strategy, state))
                    break;
                if (doStdCRemainder(C_layoutExt, false, switchedColumns,
                            remTypes, fragments, fragPositives, fragSizes,
                            C_addr0, op, masks, problem, strategy, state))
                    break;
            }
            return false;
        } while (false);

        // Free address header for block 0.
        for (int q = 0; q < C_count; q++)
            state.ra.safeRelease(C_addr0[q]);

        // Free C mask registers.
        releaseMaskAssignments(masks, state);

        // Prepare for load/store descriptor generation.
        if (remDescs[0] || remDescs[1])
            setupTeardownLoadStoreDesc(false, strategy, state);
    }

    // Do alternate C remainder handling if enabled.
    if (altCRemainder) {
        if (stdCRemainder) {
            if (state.isNested || (op != COperation::UpdateStore))
                jmpi(1, labelAltCRemDone);
            else
                epilogue(strategy, state);
        }
        mark(labelAltCRemainder);
        doAlternateCRemainder(op, problem, strategy, state);
        mark(labelAltCRemDone);
    }

    // C accumulators were converted back to the regular C type.
    state.Tacc = problem.Tc;

    if (state.allowEmptyC && (remainderM || remainderN)) {
        mark(labelSkip);
        if (problem.fused) join(16);
    }

    return true; /* Successful! */
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmBodyInternal(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {

    // Accumulate C with panel*panel multiply.
    if (!gemmAccumulateC(problem, strategy, state)) return false;

    // Late exit.
    bool lateExit = (strategy.slmBuffers > 0);
    Label labelLateExit;

    if (lateExit) {
        int simt = problem.fused ? 16 : 1;

        cmp(simt | le | f0[0], state.remainders[LoopM], uint16_t(0));
        cmp(simt | le | f1[0], state.remainders[LoopN], uint16_t(0));

        InstructionModifier cond = simt | f0[0] | anyv;

        problem.fused ? goto12(cond, labelLateExit)
                      : ejmpi(cond, labelLateExit);
    }

    // Update C. If configured, choose between regular beta and beta = 0 or beta = 1 updates now.
    //   beta = 1 flag (for trmm) can vary between fused threads.
    bool checkBeta0 = problem.checkBeta0 && !problem.beta_real.fixed();
    bool checkBeta1 = state.beta1.isValid();
    if (!checkBeta0 && !checkBeta1) {
        if (!gemmUpdateC(problem, strategy, state)) return false;
    } else {
        if (checkBeta0 && checkBeta1) stub();

        auto modProblem = problem;
        modProblem.beta_real = checkBeta1 ? 1 : 0;
        modProblem.beta_imag = 0;

        Label labelBetaSpecial, labelBetaDone;
        InstructionModifier mod = 1 | state.flagAP;
        bool simtCF = false;

        if (checkBeta1) {
            simtCF = problem.fused;
            if (simtCF) {
                mod = 16 | ~state.flagAP;
                cmp(16 | lt | state.flagAP, null.d(), state.beta1, int16_t(0));
            } else
                cmp(1 | lt | state.flagAP, null.d(), state.beta1, int16_t(0));
        } else {
            cmp0(1 | eq | state.flagAP, problem.beta_real.getReg(0));
        }

        simtCF ? if_(mod, labelBetaSpecial, labelBetaDone)
               : jmpi(mod, labelBetaSpecial);

        state.ra.safeRelease(state.beta1);

        auto modState = state;

        if (!gemmUpdateC(problem, strategy, modState)) return false;

        simtCF ? else_(16, labelBetaDone)
               : state.isNested ? jmpi(1, labelBetaDone)
                                : epilogue(strategy, state);

        mark(labelBetaSpecial);

        if (!gemmUpdateC(modProblem, strategy, state)) return false;

        mark(labelBetaDone);

        if (simtCF) endif(16);
    }

    if (lateExit) {
        mark(labelLateExit);
        if (problem.fused) join(16);
    }

    return true;
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::maySLMSplitM(
        const GEMMProblem &problem, const GEMMStrategy &strategy) {
    if (!strategy.slmA) return false;
    if (!isColMajor(problem.A.layout) ^ isTransposing(strategy.A.accessType))
        return true;
    return strategy.slmMBlockSplit;
}

template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::maySLMSplitN(
        const GEMMProblem &problem, const GEMMStrategy &strategy) {
    if (!strategy.slmB) return false;
    if (isColMajor(problem.B.layout) ^ isTransposing(strategy.B.accessType))
        return true;
    return strategy.slmNBlockSplit;
}

// Check whether all threads in a thread group should stay together in m/n remainder handling
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::wgRemCheck(
        const GEMMProblem &problem, const GEMMStrategy &strategy) {
    return (maySLMSplitM(problem, strategy)
                   && (strategy.remHandling[LoopM] != RemainderHandling::Ignore)
                   && !problem.A.padded)
            || (maySLMSplitN(problem, strategy)
                    && (strategy.remHandling[LoopN]
                            != RemainderHandling::Ignore)
                    && !problem.B.padded);
}

// Do outer-level m/n remainder handling.
template <ngen::HW hw>
template <typename Problem>
bool gemm_kernel_generator_t<hw>::mnRemainderHandling(LoopType loop,
        Problem &problem, GEMMStrategy &strategy, GEMMState &state,
        bool (gemm_kernel_generator_t<hw>::*func)(
                Problem, GEMMStrategy, GEMMState)) {
    auto method = strategy.remHandling[loop];
    auto &unroll = strategy.unroll[loop];
    auto mn = (loop == LoopM) ? state.inputs.m : state.inputs.n;
    auto splitThresh
            = (loop == LoopM) ? strategy.mSplitThresh : strategy.nSplitThresh;

    Label label_done;

    auto originalCheckAdd32 = strategy.checkAdd32;

    if (method == RemainderHandling::Split) {
        Label label_remainder;

        // Jump to remainder loop if needed.
        // If threads fused in this direction, factor fused ID into calculation.
        if (wgRemCheck(problem, strategy))
            cmp(1 | lt | f0[0], null.d(), state.remaindersWG[loop],
                    uint16_t(unroll * strategy.wg[loop]));
        else
            cmp(1 | lt | f0[0], null.d(), state.remaindersFused[loop],
                    uint16_t(unroll));

        if (splitThresh) {
            cmp(1 | lt | f1[0], null.d(), mn, int32_t(splitThresh));
            ejmpi(1 | f0[0] | anyv, label_remainder);
        } else
            jmpi(1 | f0[0], label_remainder);

        // First generate code that ignores remainder handling.
        GEMMStrategy substrategy = strategy;
        substrategy.remHandling[loop] = RemainderHandling::Ignore;

        status << "Generating "
               << "MNK"[static_cast<int>(loop)]
               << " non-remainder kernel for unroll " << unroll << '.'
               << status_stream::endl;
        if (!(this->*func)(problem, substrategy, state)) {
            status << "Non-remainder kernel failed, aborting."
                   << status_stream::endl;
            return false;
        }

        // Return, unless this is part of a larger computation, in which case jump to end.
        if (state.isNested)
            jmpi(1, label_done);
        else
            epilogue(strategy, state);

        mark(label_remainder);

        strategy.checkAdd32 = false;
    }

    // OK, great! Now try to create remainder-handling code.
    status << "Attempting to generate "
           << "MNK"[static_cast<int>(loop)] << " general kernel for unroll "
           << unroll << '.' << status_stream::endl;
    bool success = (this->*func)(problem, strategy, state);

    strategy.checkAdd32 = originalCheckAdd32;
    if (success) {
        mark(label_done);
        return true;
    }

#ifndef ALLOW_REMAINDERS
    // Disable remainder code for now.
    return false;
#else
    auto &bound = (loop == LoopN) ? state.inputs.n : state.inputs.m;
    auto &index = (loop == LoopN) ? state.j0 : state.i0;
    auto &remainders = state.remainders[loop];

    if (method == RemainderHandling::Ignore)
        throw std::runtime_error("Could not generate kernel.");

    // It failed, so break up the loop into the next smaller power of 2 along this dimension,
    //  plus the remainder (recursively).
    Label label_next_rem;

    if (unroll == 1) {
        // No more splitting to do.
        // We don't know if this was originally split, so just output a warning.
        status << "NOTE: Split remainder handling is required for loop "
               << "MNK"[static_cast<int>(loop)] << '.' << status_stream::endl;
        return true;
    }
    int chunkSize = rounddown_pow2(unroll - 1);

    // Jump to next remainder loop if needed.
    pushStream();
    {
        cmp(1 | lt | state.flagAP, null.d(), remainders, chunkSize);
        jmpi(1 | state.flagAP, label_next_rem);

        {
            GEMMStrategy substrategy = strategy;
            GEMMState substate = state;
            substrategy.remHandling[loop] = RemainderHandling::Ignore;
            substrategy.unroll[loop] = chunkSize;
            substate.isNested = true;
            status << "Generating "
                   << "MNK"[static_cast<int>(loop)]
                   << " remainder kernel with unroll " << chunkSize << '.'
                   << status_stream::endl;
            if (!(this->*func)(problem, substrategy, substate)) {
                discardStream();
                return false;
            }
        }

        // Adjust remainder.
        add(1, remainders, remainders, -chunkSize);

        // Adjust pointers as needed.
        // A += i0 (N) i0 * lda (T, Pc)
        // B += j0 * ldb (N, Pr) j0 (T)
        // C += i0 + j0 * ldc (N, Pr) j0 + i0 * ldc (T, Pc)
        switch (loop) {
            case LoopM:
                if (problem.A.layout == MatrixLayout::N)
                    eadd(1, state.effA, state.effA, chunkSize * Ta, strategy,
                            state);
                else {
                    Subregister temp = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, temp, state.inputs.lda, chunkSize);
                    eadd(1, state.effA, state.effA, temp, strategy, state);
                    state.ra.safeRelease(temp);
                }
                if (problem.C.layout == MatrixLayout::N
                        || problem.C.layout == MatrixLayout::Pr)
                    eadd(1, state.effC, state.effC,
                            chunkSize * transaction_safe, strategy, state);
                else {
                    Subregister temp = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, temp, state.inputs.lda, chunkSize);
                    eadd(1, state.effA, state.effA, temp, strategy, state);
                    state.ra.safeRelease(temp);
                }
                break;
            case LoopN:
                if (problem.B.layout == MatrixLayout::T)
                    eadd(1, state.effB, state.effB, chunkSize * Tb, strategy,
                            state);
                else {
                    Subregister temp = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, temp, state.inputs.ldb, chunkSize);
                    eadd(1, state.effB, state.effB, temp, strategy, state);
                    state.ra.safeRelease(temp);
                }
                if (problem.C.layout == MatrixLayout::T
                        || problem.C.layout == MatrixLayout::Pc)
                    eadd(1, state.effC, state.effC, chunkSize * Tc, strategy,
                            state);
                else {
                    Subregister temp = state.ra.alloc_sub<uint32_t>();
                    mulConstant(1, temp, state.inputs.ldb, chunkSize);
                    eadd(1, state.effB, state.effB, temp, strategy, state);
                    state.ra.safeRelease(temp);
                }
                break;
        }

        mark(label_next_rem);

        // Handle the remainder recursively.
        {
            GEMMStrategy substrategy = strategy;
            substrategy.remHandling[loop] = RemainderHandling::General;
            substrategy.unroll[loop] -= chunkSize;
            if (!mnRemainderHandling(loop, problem, substrategy, state, func)) {
                discardStream();
                return false;
            }
        }
    } /* end stream */

    appendCurrentStream();

    return true; /* success */
#endif
}

template <ngen::HW hw>
template <typename Problem>
bool gemm_kernel_generator_t<hw>::mnJointSplitRemainderHandling(
        Problem &problem, GEMMStrategy &strategy, GEMMState &state,
        bool (gemm_kernel_generator_t<hw>::*func)(
                Problem, GEMMStrategy, GEMMState)) {
    Label label_done, label_remainder;
    bool success = false;

    auto unrollM = strategy.unroll[LoopM];
    auto unrollN = strategy.unroll[LoopN];

    pushStream();
    do {
        // Jump to remainder loop if needed:
        //  - if m/n below split thresholds (when enabled)
        //  - if in a remainder kernel.
        bool wgCheck = wgRemCheck(problem, strategy);

        if (strategy.mSplitThresh && strategy.nSplitThresh) {
            cmp(1 | lt | f0[0], null.d(), state.inputs.m,
                    int32_t(strategy.mSplitThresh));
            cmp(1 | lt | f1[0], null.d(), state.inputs.n,
                    int32_t(strategy.nSplitThresh));
            ejmpi(1 | f0[0] | anyv, label_remainder);
        } else if (strategy.mSplitThresh) {
            cmp(1 | lt | f0[0], null.d(), state.inputs.m,
                    int32_t(strategy.mSplitThresh));
            jmpi(1 | f0[0], label_remainder);
        } else if (strategy.nSplitThresh) {
            cmp(1 | lt | f0[0], null.d(), state.inputs.n,
                    int32_t(strategy.nSplitThresh));
            jmpi(1 | f0[0], label_remainder);
        }
        if (wgCheck) {
            cmp(1 | lt | f0[0], null.d(), state.remaindersWG[LoopM],
                    uint16_t(unrollM * strategy.wg[LoopM]));
            cmp(1 | lt | f1[0], null.d(), state.remaindersWG[LoopN],
                    uint16_t(unrollN * strategy.wg[LoopN]));
        } else {
            cmp(1 | lt | f0[0], null.d(), state.remaindersFused[LoopM],
                    uint16_t(unrollM));
            cmp(1 | lt | f1[0], null.d(), state.remaindersFused[LoopN],
                    uint16_t(unrollN));
        }
        ejmpi(1 | f0[0] | anyv, label_remainder);

        // First generate code that ignores remainder handling.
        GEMMStrategy substrategy = strategy;
        substrategy.remHandling[LoopM] = RemainderHandling::Ignore;
        substrategy.remHandling[LoopN] = RemainderHandling::Ignore;

        status << "Generating MN non-remainder kernel." << status_stream::endl;
        if (!(this->*func)(problem, substrategy, state)) {
            status << "Non-remainder kernel failed, aborting."
                   << status_stream::endl;
            break;
        }

        // Return, unless this is part of a larger computation, in which case jump to end.
        if (state.isNested)
            jmpi(1, label_done);
        else
            epilogue(strategy, state);

        mark(label_remainder);

        // Finally, generate remainder handling kernel.
        substrategy = strategy;
        substrategy.remHandling[LoopM] = substrategy.remHandling[LoopN]
                = (wgCheck ? RemainderHandling::General
                           : RemainderHandling::KnownRemainder);
        substrategy.checkAdd32 = false;
        status << "Generating MN general kernel." << status_stream::endl;
        success = (this->*func)(problem, substrategy, state);

        mark(label_done);
    } while (false);

    success ? appendCurrentStream() : discardStream();

    return success;
}

// Handle outer-level m edge cases.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmMEdge(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState &state) {
    if (strategy.jointSplit
            && strategy.remHandling[LoopM] == RemainderHandling::Split
            && strategy.remHandling[LoopN] == RemainderHandling::Split)
        return mnJointSplitRemainderHandling(problem, strategy, state,
                &gemm_kernel_generator_t<hw>::gemmBody);
    else
        return mnRemainderHandling(LoopM, problem, strategy, state,
                &gemm_kernel_generator_t<hw>::gemmNEdge);
}

// Handle outer-level n edge cases.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::gemmNEdge(
        GEMMProblem problem, GEMMStrategy strategy, GEMMState state) {
    return mnRemainderHandling(LoopN, problem, strategy, state,
            &gemm_kernel_generator_t<hw>::gemmBody);
}

// Initialize the state structure.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmInitState(GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState &state, bool inSK) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    Subregister localSize[3];
    GRF localID[3];
    Subregister tgids[3]
            = {r0.ud(1), r0.ud(6), r0.ud(7)}; // X, Y, Z threadgroup IDs

    initState(problem, strategy, state);

    if (strategy.barrierFreq > 0) interface.requireBarrier();

    if (strategy.slmBuffers > 0) {
        auto wgX = strategy.wg[strategy.loopOrder[0]];
        auto wgY = strategy.wg[strategy.loopOrder[1]];

        size_t slmSize = strategy.slmTotal(Ta, Tb, state);
        if (problem.abOffset == ABOffset::Calc) {
            // Ensure enough space for row/column sums.
            slmSize = std::max<size_t>(slmSize,
                    (strategy.unroll[LoopM] * strategy.wg[LoopM]
                            + strategy.unroll[LoopN] * strategy.wg[LoopN])
                            * Tc);
        }
        status << "SLM usage: " << slmSize / 1024. << 'k'
               << status_stream::endl;

        interface.requireSLM(slmSize);
        interface.requireBarrier();
        interface.requireWorkgroup(strategy.subgroupSize * wgX, wgY, 1);
    }

    interface.finalize();

    if (problem.wgSupport) {
        for (int dim = 0; dim < 3; dim++) {
            localID[dim] = interface.getLocalID(dim);
            localSize[dim] = interface.getLocalSize(dim);
        }
    }

    // Get input arguments.
    state.inputs.base = interface.getArgumentIfExists("base");
    if (state.inputs.base.isInvalid()) {
        state.inputs.A = interface.getArgumentIfExists("A");
        state.inputs.B = interface.getArgumentIfExists("B");
        state.inputs.C[1] = interface.getArgumentIfExists("P");
        state.inputs.surfaceA = interface.getArgumentSurface("A");
        state.inputs.surfaceB = interface.getArgumentSurface("B");
        if (state.inputs.C[1].isValid())
            state.inputs.surfaceC[1] = interface.getArgumentSurface("P");
    } else {
        state.inputs.A = state.inputs.B = state.inputs.base;
        state.inputs.surfaceA = state.inputs.surfaceB
                = interface.getArgumentSurface("base");
        if (interface.getArgumentIfExists("offset_P").isValid()) {
            state.inputs.C[1] = state.inputs.base;
            state.inputs.surfaceC[1] = state.inputs.surfaceA;
        }
    }

    state.inputs.C[0] = interface.getArgumentIfExists("C");
    state.inputs.surfaceC[0] = interface.getArgumentSurface("C");
    state.C_count = state.inputs.C[1].isValid() ? 2 : 1;
    if (problem.cOffset != COffset::None) {
        state.inputs.CO = interface.getArgumentIfExists("CO");
        state.inputs.surfaceCO = interface.getArgumentSurface("CO");
    }

    if (problem.abOffset != ABOffset::None) {
        auto abo = interface.getArgumentIfExists("abo");
        if (abo.isValid()) {
            // A/B offset are two words packed into a single dword argument.
            state.inputs.ao = abo.w(0);
            state.inputs.bo = abo.w(1);
        } else {
            state.inputs.ao = interface.getArgumentIfExists("ao");
            state.inputs.bo = interface.getArgumentIfExists("bo");
        }
    }
    state.inputs.offsetA = interface.getArgumentIfExists("offset_A");
    state.inputs.offsetB = interface.getArgumentIfExists("offset_B");
    state.inputs.offsetC[0] = interface.getArgumentIfExists("offset_C");
    state.inputs.offsetC[1] = interface.getArgumentIfExists("offset_P");
    state.inputs.offsetCO = interface.getArgumentIfExists("offset_CO");
    if (problem.batch == BatchMode::Strided) {
        state.inputs.strideA[0] = interface.getArgumentIfExists("stride_A");
        state.inputs.strideB[0] = interface.getArgumentIfExists("stride_B");
        state.inputs.strideC[0] = interface.getArgumentIfExists("stride_C");
        if (problem.batchDims > 1) {
            state.inputs.strideA[1]
                    = interface.getArgumentIfExists("stride_A1");
            state.inputs.strideB[1]
                    = interface.getArgumentIfExists("stride_B1");
            state.inputs.strideC[1]
                    = interface.getArgumentIfExists("stride_C1");
            state.inputs.batchSize1
                    = interface.getArgumentIfExists("batch_size1");
            state.inputs.recipBatchSize1
                    = interface.getArgumentIfExists("recip_batch_size1");
        }
    } else if (problem.batch == BatchMode::Nonstrided)
        state.inputs.offsetBatch
                = interface.getArgumentIfExists("offset_batch");
    state.inputs.lda = interface.getArgumentIfExists("lda");
    state.inputs.ldb = interface.getArgumentIfExists("ldb");
    state.inputs.ldc[0] = interface.getArgumentIfExists("ldc");
    state.inputs.ldc[1] = interface.getArgumentIfExists("ldp");
    state.inputs.m = interface.getArgumentIfExists("m");
    state.inputs.n = interface.getArgumentIfExists("n");
    state.inputs.k = interface.getArgumentIfExists("k");
    state.inputs.k0 = interface.getArgumentIfExists("k0");
    state.inputs.alpha_real = interface.getArgumentIfExists("alpha_real");
    state.inputs.alpha_imag = interface.getArgumentIfExists("alpha_imag");
    state.inputs.beta_real = interface.getArgumentIfExists("beta_real");
    state.inputs.beta_imag = interface.getArgumentIfExists("beta_imag");
    state.inputs.mapping = interface.getArgumentIfExists("mapping");
    state.inputs.diagA = interface.getArgumentIfExists("diag_A");
    state.inputs.diagB = interface.getArgumentIfExists("diag_B");
    state.inputs.diagC = interface.getArgumentIfExists("diag_C");
    state.inputs.flags = interface.getArgumentIfExists("flags");

    if (state.inputs.lda.isInvalid()) state.inputs.lda = state.inputs.k;
    if (state.inputs.ldb.isInvalid()) state.inputs.ldb = state.inputs.k;

    Subregister tgids_reordered[3];
    GRF lids_reordered[3];
    Subregister lszs_reordered[3];

    for (int l = 0; l < 3; l++) {
        int i = static_cast<int>(strategy.loopOrder[l]);
        tgids_reordered[i] = tgids[l];
        lids_reordered[i] = localID[l];
        lszs_reordered[i] = localSize[l];
    }
    state.inputs.groupIDM = tgids_reordered[0];
    state.inputs.groupIDN = tgids_reordered[1];
    state.inputs.groupIDK = tgids_reordered[2];
    state.inputs.localIDM = lids_reordered[0];
    state.inputs.localIDN = lids_reordered[1];
    state.inputs.localIDK = lids_reordered[2];
    state.inputs.localSizeM = lszs_reordered[0];
    state.inputs.localSizeN = lszs_reordered[1];
    state.inputs.localSizeK = lszs_reordered[2];

    // Downgrade offsets to 32 bits for non-A64 accesses.
    if (problem.A.base.getModel() != ModelA64)
        state.inputs.offsetA = state.inputs.offsetA.d();
    if (problem.B.base.getModel() != ModelA64)
        state.inputs.offsetB = state.inputs.offsetB.d();
    if (problem.C.base.getModel() != ModelA64)
        for (int q = 0; q < state.C_count; q++)
            state.inputs.offsetC[q] = state.inputs.offsetC[q].d();
    if (problem.cOffset != COffset::None
            && problem.CO.base.getModel() != ModelA64)
        state.inputs.offsetCO = state.inputs.offsetCO.d();

    // For now, reinterpret m/n/k/ld/diag variables to 32-bit if they are 64-bit.
    state.inputs.m = state.inputs.m.d();
    state.inputs.n = state.inputs.n.d();
    state.inputs.k = state.inputs.k.d();
    state.inputs.lda = state.inputs.lda.ud();
    state.inputs.ldb = state.inputs.ldb.ud();
    for (int q = 0; q < state.C_count; q++)
        state.inputs.ldc[q] = state.inputs.ldc[q].ud();
    state.inputs.diagA = state.inputs.diagA.d();
    state.inputs.diagB = state.inputs.diagB.d();
    state.inputs.diagC = state.inputs.diagC.d();

    // Claim registers.
    for (int i = 0; i < 4; i++)
        state.ra.claim(r0.uq(i));

    if (problem.A.base.isStateless()) {
        state.effA = state.inputs.A;
        state.ra.claim(state.inputs.A);
    } else
        state.effA = state.inputs.offsetA.d();

    if (problem.B.base.isStateless()) {
        state.effB = state.inputs.B;
        state.ra.claim(state.inputs.B);
    } else
        state.effB = state.inputs.offsetB.d();

    for (int q = 0; q < state.C_count; q++) {
        if (problem.C.base.isStateless()) {
            state.effC[q] = state.inputs.C[q];
            state.ra.claim(state.inputs.C[q]);
        } else
            state.effC[q] = state.inputs.offsetC[q].d();
    }

    if (problem.abOffset != ABOffset::None) {
        state.ra.claim(state.inputs.ao);
        state.ra.claim(state.inputs.bo);
    }

    if (problem.cOffset != COffset::None) {
        if (problem.CO.base.isStateless()) {
            state.effCO = state.inputs.CO;
            state.ra.claim(state.inputs.CO);
        } else
            state.effCO = state.inputs.offsetCO.d();
        state.ra.claim(state.inputs.offsetCO);
    }

    state.ra.claim(state.inputs.offsetA);
    state.ra.claim(state.inputs.offsetB);
    for (int q = 0; q < state.C_count; q++)
        state.ra.claim(state.inputs.offsetC[q]);
    state.ra.claim(state.inputs.lda);
    state.ra.claim(state.inputs.ldb);
    for (int q = 0; q < state.C_count; q++)
        state.ra.claim(state.inputs.ldc[q]);
    state.ra.claim(state.inputs.m);
    state.ra.claim(state.inputs.n);
    state.ra.claim(state.inputs.k);
    if (strategy.kBlocking) state.ra.claim(state.inputs.k0);

    if (!problem.alpha_real.fixed()) {
        state.ra.claim(state.inputs.alpha_real);
        problem.alpha_real = state.inputs.alpha_real;
    }
    if (!problem.beta_real.fixed()) {
        state.ra.claim(state.inputs.beta_real);
        problem.beta_real = state.inputs.beta_real;
    }

    if (problem.wgSupport && !inSK) {
        state.ra.claim(state.inputs.localIDM);
        state.ra.claim(state.inputs.localIDN);
        state.ra.claim(state.inputs.localSizeM);
        state.ra.claim(state.inputs.localSizeN);
        if (strategy.kBlocking) {
            state.ra.claim(state.inputs.localIDK);
            state.ra.claim(state.inputs.localSizeK);
        }
    }

    if (state.inputs.flags.isValid()) state.ra.claim(state.inputs.flags);

    if (problem.batch == BatchMode::Strided) {
        for (int i = 0; i < problem.batchDims; i++) {
            state.ra.claim(state.inputs.strideA[i]);
            state.ra.claim(state.inputs.strideB[i]);
            state.ra.claim(state.inputs.strideC[i]);
        }
        state.ra.claim(state.inputs.groupIDK);
    } else if (problem.batch == BatchMode::Nonstrided) {
        state.ra.claim(state.inputs.offsetBatch);
        state.ra.claim(state.inputs.groupIDK);
    }

    state.isNested = problem.fused;
    state.flagAP = state.raVFlag.alloc();
    state.fused.copyA = state.fused.copyB = false;

    state.allocEmulate64Temp(strategy.emulate);

    state.Tacc = problem.Tc;
    state.copyC = (problem.Tc != problem.Tc_ext)
            || (!strategy.altCRemainder && (Tc.size() < 4));

    state.broadcast = strategy.doubleWA;
}

// Offset A pointer in k dimension by a constant value.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmOffsetAk(int h,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    auto Ta = problem.Ta;
    if (strategy.A.address2D) stub();
    if (h) switch (problem.A.layout) {
            case MatrixLayout::T:
                eadd(1, state.effA, state.effA, h * Ta, strategy, state);
                break;
            case MatrixLayout::Pc:
                eadd(1, state.effA, state.effA, h * problem.A.packSize * Ta,
                        strategy, state);
                break;
            case MatrixLayout::N:
                emad(1, state.effA, state.effA, state.inputs.lda,
                        Immediate::w(h), strategy, state);
                break;
            default: stub();
        }
}

// Offset B pointer in k dimension by a constant value.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmOffsetBk(int h,
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    auto Tb = problem.Tb;
    if (strategy.B.address2D) stub();
    if (h) switch (problem.B.layout) {
            case MatrixLayout::N:
                eadd(1, state.effB, state.effB, h * Tb, strategy, state);
                break;
            case MatrixLayout::Pr:
                eadd(1, state.effB, state.effB, h * problem.B.packSize * Tb,
                        strategy, state);
                break;
            case MatrixLayout::T:
                emad(1, state.effB, state.effB, state.inputs.ldb,
                        Immediate::w(h), strategy, state);
                break;
            default: stub();
        }
}

// Adjust A, B, C to start at (i0, j0).
//  initial is true to adjust offset_{A,B,C}, false to adjust A,B,C pointers.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmOffsetABC(bool initial, Subregister i0,
        Subregister j0, Subregister h0, GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState &state, bool doA, bool doB,
        bool doC) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    auto offsetA = initial ? state.inputs.offsetA : state.effA;
    auto offsetB = initial ? state.inputs.offsetB : state.effB;
    bool doCO = doC && (problem.cOffset != COffset::None);
    bool batchedS = (problem.batch == BatchMode::Strided);

    Subregister tempQ0 = state.ra.alloc_sub<int64_t>(
            getHint(HintType::TempComp0, strategy));
    Subregister tempD0 = tempQ0.d();
    Subregister tempQ1 = state.ra.alloc_sub<int64_t>(
            getHint(HintType::TempComp1, strategy));
    Subregister tempD1 = tempQ1.d();

    if (strategy.A.address2D) doA = false;
    if (strategy.B.address2D) doB = false;
    if (strategy.C.address2D) doC = false;

    // To do: interleave code.
    // A += i0 (N) i0 * lda (T, Pc)
    // B += j0 * ldb (N, Pr) j0 (T)
    // C += i0 + j0 * ldc (N, Pr) j0 + i0 * ldc (T, Pc)
    // CO += i0 (row offsets) j0 (col offsets)
    if (doA && i0.isValid()) {
        if (problem.A.layout == MatrixLayout::Nontranspose) {
            if (initial || (Ta.size() == 1))
                eadd(1, offsetA, offsetA, i0, strategy, state);
            else {
                mulConstant(1, tempD1, i0, Ta.size());
                eadd(1, offsetA, offsetA, tempD1, strategy, state);
            }
        } else {
            emul(1, tempQ1, i0, state.inputs.lda, strategy, state);
            eadd(1, offsetA, offsetA, tempQ1.reinterpret(0, offsetA.getType()),
                    strategy, state);
        }
        if (initial && batchedS) {
            for (int b = 0; b < problem.batchDims; b++)
                emul(1, state.inputs.strideA[b], state.inputs.strideA[b],
                        state.batchID[b], strategy, state);
            for (int b = 0; b < problem.batchDims; b++) {
                eadd(1, offsetA, offsetA, state.inputs.strideA[b], strategy,
                        state);
                state.ra.safeRelease(state.inputs.strideA[b]);
            }
        }
    }

    if (doB && j0.isValid()) {
        if (problem.B.layout == MatrixLayout::Transpose)
            if (initial || (Tb.size() == 1))
                eadd(1, offsetB, offsetB, j0, strategy, state);
            else {
                mulConstant(1, tempD0, j0, Tb.size());
                eadd(1, offsetB, offsetB, tempD0, strategy, state);
            }
        else {
            emul(1, tempQ0, j0, state.inputs.ldb, strategy, state);
            eadd(1, offsetB, offsetB, tempQ0.reinterpret(0, offsetB.getType()),
                    strategy, state);
        }
        if (initial && batchedS) {
            for (int b = 0; b < problem.batchDims; b++)
                emul(1, state.inputs.strideB[b], state.inputs.strideB[b],
                        state.batchID[b], strategy, state);
            for (int b = 0; b < problem.batchDims; b++) {
                eadd(1, offsetB, offsetB, state.inputs.strideB[b], strategy,
                        state);
                state.ra.safeRelease(state.inputs.strideB[b]);
            }
        }
    }

    FlagRegister flagCOR, flagCOC;
    if (doCO) {
        flagCOR = state.raVFlag.alloc();
        flagCOC = state.raVFlag.alloc();
        and_(1 | nz | flagCOC, null.ud(), state.inputs.flags, FlagCOColumn);
        and_(1 | nz | flagCOR, null.ud(), state.inputs.flags, FlagCORow);
    }
    if (doC) {
        for (int q = 0; q < state.C_count; q++) {
            auto offsetC = initial ? state.inputs.offsetC[q] : state.effC[q];

            Subregister x, y;
            switch (problem.C.layout) {
                case MatrixLayout::N:
                case MatrixLayout::Pr:
                    x = i0;
                    y = j0;
                    break;
                case MatrixLayout::T:
                case MatrixLayout::Pc:
                    x = j0;
                    y = i0;
                    break;
            }
            if (initial || (Tc.size() == 1))
                eadd(1, offsetC, offsetC, x, strategy, state);
            else {
                mulConstant(1, tempD0, x, Tc.size());
                eadd(1, offsetC, offsetC, tempD0, strategy, state);
            }
            if (initial && batchedS) {
                for (int b = 0; b < problem.batchDims; b++)
                    emul(1, state.inputs.strideC[b], state.inputs.strideC[b],
                            state.batchID[b], strategy, state);
                for (int b = 0; b < problem.batchDims; b++) {
                    eadd(1, offsetC, offsetC, state.inputs.strideC[b], strategy,
                            state);
                    state.ra.safeRelease(state.inputs.strideC[b]);
                }
            }
            emul(1, tempQ0, y, state.inputs.ldc[q], strategy, state);
            eadd(1, offsetC, offsetC, tempQ0.reinterpret(0, offsetC.getType()),
                    strategy, state); // Xe: Use add3.
        }
    }
    if (doCO) {
        auto offsetCO = initial ? state.inputs.offsetCO : state.effCO;
        eadd(1 | flagCOC, offsetCO, offsetCO, j0, strategy, state);
        eadd(1 | flagCOR, offsetCO, offsetCO, i0, strategy, state);
        state.raVFlag.safeRelease(flagCOR);
        state.raVFlag.safeRelease(flagCOC);
    }

    // When k blocking (or certain triangular source kernels)
    //   A += h0 * lda (N) h0 (T) h0 * mb (Pc)
    //   B += h0 (N) h0 * ldb (T) h0 * nb (Pr)
    if (!h0.isInvalid()) {
        if (!initial) stub();
        if (doA) switch (problem.A.layout) {
                case MatrixLayout::Nontranspose:
                    emul(1, tempQ1, h0, state.inputs.lda, strategy, state);
                    eadd(1, offsetA, offsetA,
                            tempQ1.reinterpret(0, offsetA.getType()), strategy,
                            state);
                    break;
                case MatrixLayout::Transpose:
                    eadd(1, offsetA, offsetA, h0, strategy, state);
                    break;
                case MatrixLayout::PackedColumns:
                    mulConstant(1, tempD1, h0, strategy.unroll[LoopM]);
                    eadd(1, offsetA, offsetA, tempD1, strategy, state);
                    break;
                default: stub();
            }
        if (doB) switch (problem.B.layout) {
                case MatrixLayout::Nontranspose:
                    eadd(1, offsetB, offsetB, h0, strategy, state);
                    break;
                case MatrixLayout::Transpose:
                    emul(1, tempQ0, h0, state.inputs.ldb, strategy, state);
                    eadd(1, offsetB, offsetB,
                            tempQ0.reinterpret(0, offsetB.getType()), strategy,
                            state);
                    break;
                case MatrixLayout::PackedRows:
                    mulConstant(1, tempD0, h0, strategy.unroll[LoopN]);
                    eadd(1, offsetB, offsetB, tempD0, strategy, state);
                    break;
                default: stub();
            }
    }

    gemmReleaseBatchIDs(problem, strategy, state);
    state.ra.safeRelease(tempQ0);
    state.ra.safeRelease(tempQ1);
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmSetupABC(GEMMProblem &problem,
        GEMMStrategy &strategy, GEMMState &state, bool doA, bool doB,
        bool doC) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc_ext = problem.Tc_ext;

    if (state.inputs.lda.ud() == state.inputs.k.ud()) {
        if (doA || doB) {
            if (doA && doB && (Ta.size() != Tb.size())) stub();

            state.inputs.lda = state.inputs.ldb = state.ra.alloc_sub<int32_t>();
            emulConstant(1, state.inputs.lda, state.inputs.k, Ta.size(),
                    strategy, state);
        }
    } else {
        if (doA)
            emulConstant(1, state.inputs.lda, state.inputs.lda, Ta.size(),
                    strategy, state);
        if (doB)
            emulConstant(1, state.inputs.ldb, state.inputs.ldb, Tb.size(),
                    strategy, state);
    }
    if (doC)
        for (int q = 0; q < state.C_count; q++)
            emulConstant(1, state.inputs.ldc[q], state.inputs.ldc[q],
                    Tc_ext.size(), strategy, state);

    // Add offsets to A, B, C base pointers for stateless accesses.
    if (doC) {
        for (int q = 0; q < state.C_count; q++)
            emulConstant(1, state.inputs.offsetC[q], state.inputs.offsetC[q],
                    Tc_ext.size(), strategy, state);
        if (problem.cOffset != COffset::None)
            emulConstant(1, state.inputs.offsetCO, state.inputs.offsetCO,
                    Tc_ext.size(), strategy, state);
    }
    if (doA)
        emulConstant(1, state.inputs.offsetA, state.inputs.offsetA, Ta.size(),
                strategy, state);
    if (doB)
        emulConstant(1, state.inputs.offsetB, state.inputs.offsetB, Tb.size(),
                strategy, state);

    if (doC && problem.C.base.isStateless()) {
        for (int q = 0; q < state.C_count; q++) {
            auto Csrc = state.inputs.C[q];
            if ((q > 0) && problem.C.base.isStateless()
                    && !state.inputs.base.isInvalid())
                state.effC[q] = state.inputs.C[q]
                        = state.ra.alloc_sub<uint64_t>(
                                getHint(HintType::LongTerm, strategy));

            eadd(1, state.inputs.C[q], Csrc, state.inputs.offsetC[q], strategy,
                    state);
            state.ra.safeRelease(state.inputs.offsetC[q]);
        }
    }
    if (doC && (problem.cOffset != COffset::None)
            && problem.CO.base.isStateless()) {
        eadd(1, state.inputs.CO, state.inputs.CO, state.inputs.offsetCO,
                strategy, state);
        state.ra.safeRelease(state.inputs.offsetCO);
    }
    if (doA && problem.A.base.isStateless()) {
        auto Asrc = state.inputs.A;
        if (problem.B.base.isStateless() && !state.inputs.base.isInvalid())
            state.effA = state.inputs.A = state.ra.alloc_sub<uint64_t>(
                    getHint(HintType::LongTerm, strategy));

        eadd(1, state.inputs.A, Asrc, state.inputs.offsetA, strategy, state);
        state.ra.safeRelease(state.inputs.offsetA);
    }
    if (doB && problem.B.base.isStateless()) {
        eadd(1, state.inputs.B, state.inputs.B, state.inputs.offsetB, strategy,
                state);
        state.ra.safeRelease(state.inputs.offsetB);
    }
}

// Get (possibly multidimensional) batch IDs.
template <HW hw>
void gemm_kernel_generator_t<hw>::gemmGetBatchIDs(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state) {
    switch (problem.batchDims) {
        case 0: break;
        case 1: state.batchID[0] = state.inputs.groupIDK; break;
        case 2: {
            state.batchID[0] = state.ra.alloc_sub<uint32_t>();
            state.batchID[1] = state.ra.alloc_sub<uint32_t>();
            divDown(state.batchID[1], state.inputs.groupIDK,
                    state.inputs.batchSize1, state.inputs.recipBatchSize1,
                    state.flagAP, strategy, state);
            emul(1, state.batchID[0], state.batchID[1], state.inputs.batchSize1,
                    strategy, state);
            add(1, state.batchID[0], -state.batchID[0], state.inputs.groupIDK);
            state.ra.safeRelease(state.inputs.batchSize1);
            state.ra.safeRelease(state.inputs.recipBatchSize1);
            break;
        }
        default: stub();
    }
}

template <HW hw>
void gemm_kernel_generator_t<hw>::gemmReleaseBatchIDs(
        const GEMMProblem &problem, const GEMMStrategy &strategy,
        GEMMState &state) {
    if (problem.batch != BatchMode::Strided) return;
    if (problem.batchDims == 1 && strategy.moveR0 == MoveR0::None) return;
    for (int b = 0; b < problem.batchDims; b++)
        state.ra.safeRelease(state.batchID[b]);
}

// GEMM kernel generation interface.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemm(GEMMProblem problem,
        GEMMStrategy strategy, const NEOInterfaceHandler &interface_) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;

    GEMMState state(hw);

    Label labelKernelDone;

    // By default, don't use dispatch mask.
    setDefaultNoMask();
    setDefaultAutoSWSB();

    // Set up.
    interface = interface_;
    if (problem.fused && (strategy.barrierFreq > 0)) stub();
    gemmTypeCheck(Ta, Tb, Tc);
    gemmInitState(problem, strategy, state);

    if (!problem.A.base.isStateless())
        problem.A.base.setIndex(state.inputs.surfaceA);
    if (!problem.B.base.isStateless())
        problem.B.base.setIndex(state.inputs.surfaceB);
    if (!problem.C.base.isStateless()) {
        problem.C.base.setIndex(state.inputs.surfaceC[0]);
        if (state.C_count > 1) stub();
    }
    if ((problem.cOffset != COffset::None) && !problem.CO.base.isStateless())
        problem.CO.base.setIndex(state.inputs.surfaceCO);

    // Prevent unhelpful layouts.
    if (problem.A.layout == MatrixLayout::PackedRows) stub();
    if (problem.B.layout == MatrixLayout::PackedColumns) stub();

    // Prologue.
    prologue(strategy);

    // Grab fused ID if needed, and multiply by unroll.
    getFusedID(strategy.unroll[problem.fusedLoop], problem, strategy, state);

    // Divide out subgroup size from local size 0 and local ID 0, and reorder threads for fusing if needed.
    removeSG(problem, strategy, state);
    reorderFusedEUs(problem, strategy, state);

    // Batch handling.
    gemmGetBatchIDs(problem, strategy, state);

    // 32-bit add check.
    gemmCheck32(problem, strategy, state);

    // Non-strided batch support.
    if (problem.batch == BatchMode::Nonstrided) {
        if (problem.batchDims != 1) stub();

        auto tempA = state.ra.alloc().uq();
        auto tempB = state.ra.alloc().uq();
        auto tempC = state.ra.alloc().uq();

        eadd(1, state.inputs.offsetBatch, state.inputs.offsetBatch,
                state.inputs.groupIDK, strategy, state);
        eshl(1, state.inputs.offsetBatch, state.inputs.offsetBatch, uint16_t(3),
                strategy, state);

        eadd(1, tempA[0], state.inputs.A, state.inputs.offsetBatch, strategy,
                state);
        eadd(1, tempB[0], state.inputs.B, state.inputs.offsetBatch, strategy,
                state);
        eadd(1, tempC[0], state.inputs.C[0], state.inputs.offsetBatch, strategy,
                state);

        load(1, tempA, scattered_qword(1), problem.A.base, tempA);
        load(1, tempB, scattered_qword(1), problem.B.base, tempB);
        load(1, tempC, scattered_qword(1), problem.C.base, tempC);

        emov(1, state.inputs.A, tempA, strategy);
        emov(1, state.inputs.B, tempB, strategy);
        emov(1, state.inputs.C[0], tempC, strategy);

        state.ra.safeRelease(tempA);
        state.ra.safeRelease(tempB);
        state.ra.safeRelease(tempC);
        state.ra.safeRelease(state.inputs.groupIDK);
        state.ra.safeRelease(state.inputs.offsetBatch);
    }

    // Calculate i0, j0 -- the starting row/column for this thread.
    bool needH0 = strategy.kBlocking;

    state.i0 = state.ra.alloc_sub<uint32_t>(
            getHint(HintType::TempComp0, strategy));
    state.j0 = state.ra.alloc_sub<uint32_t>(
            getHint(HintType::TempComp1, strategy));
    if (needH0)
        state.h0 = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));

    bool wgCheck = wgRemCheck(problem, strategy);
    bool gemmtBarriers = false;

    Subregister idM, idN, idK;
    Subregister wgI0, wgJ0;

    if (problem.wgSupport) {
        idM = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp1, strategy));
        idN = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));
        if (strategy.kBlocking)
            idK = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));

        mul(1, idM, state.inputs.groupIDM, state.inputs.localSizeM.uw());
        mul(1, idN, state.inputs.groupIDN, state.inputs.localSizeN.uw());
        if (strategy.kBlocking)
            mul(1, idK, state.inputs.groupIDK, state.inputs.localSizeK.uw());

        if (wgCheck || gemmtBarriers) {
            wgI0 = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp0, strategy));
            wgJ0 = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::TempComp1, strategy));
            mulConstant(1, wgI0, idM, strategy.unroll[LoopM]);
            mulConstant(1, wgJ0, idN, strategy.unroll[LoopN]);
        }

        add(1, idM, idM, state.inputs.localIDM);
        add(1, idN, idN, state.inputs.localIDN);
        if (strategy.kBlocking) add(1, idK, idK, state.inputs.localIDK);
    } else {
        idM = state.inputs.groupIDM;
        idN = state.inputs.groupIDN;
        idK = state.inputs.groupIDK;
    }

    if (strategy.slmBuffers > 0) saveLocalIDs(strategy, state);

    {
        mulConstant(1, state.i0, idM, strategy.unroll[LoopM]);
        mulConstant(1, state.j0, idN, strategy.unroll[LoopN]);
    }
    if (strategy.kBlocking)
        emul(1, state.h0, idK, state.inputs.k0, strategy, state);

    // Reverse m/n loops if requested.
    for (LoopType l : {LoopM, LoopN})
        if (strategy.reverse[l]) {
            bool fusedL = problem.fused && (l == problem.fusedLoop);
            auto q = (l == LoopM) ? state.inputs.m : state.inputs.n;
            auto q0 = (l == LoopM) ? state.i0 : state.j0;
            auto q0Align = state.ra.alloc_sub<uint32_t>();
            auto temp = state.ra.alloc_sub<uint32_t>();

            add(1, q0Align, q, -1);
            if (strategy.fixedWG()) {
                mod(temp, q0, strategy.wg[l] * strategy.unroll[l], strategy,
                        state);
                alignDown(q0Align, q0Align, strategy.wg[l] * strategy.unroll[l],
                        strategy, state);
                shl(1, temp, temp, 1);
                eadd3(1 | ge | f0[0], q0Align.d(), q0Align, -q0, temp);
                mov(1 | f0[0], q0, q0Align);
            } else if (fusedL) {
                shl(1, temp, state.fusedID, 1);
                alignDown(q0Align, q0Align, 2 * strategy.unroll[l], strategy,
                        state);
                eadd3(1 | ge | f0[0], q0Align.d(), q0Align, -q0, temp);
                mov(1 | f0[0], q0, q0Align);
            } else {
                alignDown(
                        q0Align, q0Align, strategy.unroll[l], strategy, state);
                cmp(1 | le | f0[0], q0, q0Align);
                add(1 | f0[0], q0, q0Align, -q0);
            }
            state.ra.safeRelease(temp);
            state.ra.safeRelease(q0Align);
        }

    if (problem.wgSupport) {
        state.ra.safeRelease(idM);
        state.ra.safeRelease(idN);
        state.ra.safeRelease(idK);
        state.ra.safeRelease(state.inputs.localIDM);
        state.ra.safeRelease(state.inputs.localIDN);
        state.ra.safeRelease(state.inputs.localSizeM);
        state.ra.safeRelease(state.inputs.localSizeN);
        if (strategy.kBlocking) {
            state.ra.safeRelease(state.inputs.localIDK);
            state.ra.safeRelease(state.inputs.localSizeK);
        }
    }

    moveR0(strategy, state);
    if (problem.batch == BatchMode::Strided)
        state.ra.claim(state.inputs.groupIDK);

    // Adjust k range as needed.
    if (strategy.kBlocking) {
        add(1, state.inputs.k, state.inputs.k, -state.h0);
        min_(1, state.inputs.k, state.inputs.k, state.inputs.k0);
        state.ra.safeRelease(state.inputs.k0);
    }

    // Compute workgroup remainders if needed.
    if (wgCheck) {
        state.remaindersWG[LoopM] = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp1, strategy));
        state.remaindersWG[LoopN] = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));
        add(1 | sat, state.remaindersWG[LoopM], -wgI0, state.inputs.m);
        add(1 | sat, state.remaindersWG[LoopN], -wgJ0, state.inputs.n);
    }
    state.ra.safeRelease(wgI0);
    state.ra.safeRelease(wgJ0);

    // Compute base addresses for A, B, C.
    gemmOffsetABC(true, state.i0, state.j0, state.h0, problem, strategy, state);

    gemmSetupABC(problem, strategy, state);
    gemmSubkernel(problem, strategy, state);

    mark(labelKernelDone);
    epilogue(strategy, state);
    padding();
}

// Calculate and cache lda_ka (= lda * ka) and ldb_kb (= ldb * kb) as necessary.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmCalcIncrements(const GEMMProblem &problem,
        const GEMMStrategy &strategy, GEMMState &state, int ka_load,
        int kb_load) {
    if (ka_load == 0) ka_load = strategy.ka_inc();
    if (kb_load == 0) kb_load = strategy.kb_inc();

    // If A is nontranspose, we need lda * ka_load * elementSize.
    if (problem.A.layout == MatrixLayout::N && ka_load > 1
            && !strategy.A.address2D) {
        if (state.lda_ka.isInvalid())
            state.lda_ka = state.ra.alloc_sub<uint32_t>();
        emulConstant(
                1, state.lda_ka, state.inputs.lda, ka_load, strategy, state);
        state.ka_cached = ka_load;
    }
    // Similarly for B if it's transpose.
    if (problem.B.layout == MatrixLayout::T && kb_load > 1
            && !strategy.B.address2D) {
        if (state.ldb_kb.isInvalid())
            state.ldb_kb = state.ra.alloc_sub<uint32_t>();
        emulConstant(
                1, state.ldb_kb, state.inputs.ldb, kb_load, strategy, state);
        state.kb_cached = kb_load;
    }
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmSubkernel(
        GEMMProblem &problem, GEMMStrategy &strategy, GEMMState state) {
    Label labelSubkernelDone;

    status << "Begin subkernel: unroll " << strategy.unroll[LoopM] << 'x'
           << strategy.unroll[LoopN] << status_stream::endl;

    // Calculate remainders for m/n loops: clamp(m - i0, 0, unrollM), clamp(n - j0, 0, unrollN).
    // Careful with this clamping, because unroll may change in remainder handling.
    bool remM = (strategy.remHandling[LoopM] != RemainderHandling::Ignore);
    bool remN = (strategy.remHandling[LoopN] != RemainderHandling::Ignore);
    bool fusedremM = remM && problem.fused && (problem.fusedLoop == LoopM);
    bool fusedremN = remN && problem.fused && (problem.fusedLoop == LoopN);
    bool earlyExit = (strategy.slmBuffers == 0);

    if (fusedremM || fusedremN) {
        state.remFusedStorage = state.ra.alloc_sub<uint32_t>();
        if (earlyExit) {
            if (remM) cmp(16 | ge | f0[1], null.d(), state.i0, state.inputs.m);
            if (remN) cmp(16 | ge | f1[1], null.d(), state.j0, state.inputs.n);
        }
        add(1, state.remFusedStorage, -state.fusedID,
                uint16_t(strategy.unroll[problem.fusedLoop]));
    }
    if (remM || !earlyExit) {
        state.remaindersFused[LoopM] = state.remainders[LoopM]
                = state.ra.alloc_sub<uint32_t>();
        InstructionModifier mod = 1 | sat;
        if (!problem.fused && earlyExit) mod = mod | le | f0[1];
        add(mod, state.remainders[LoopM], -state.i0, state.inputs.m);
    }
    if (remN || !earlyExit) {
        state.remaindersFused[LoopN] = state.remainders[LoopN]
                = state.ra.alloc_sub<uint32_t>();
        InstructionModifier mod = 1 | sat;
        if (!problem.fused && earlyExit) mod = mod | le | f1[1];
        add(mod, state.remainders[LoopN], -state.j0, state.inputs.n);
    }
    if (fusedremM || fusedremN) {
        state.remaindersFused[problem.fusedLoop] = state.remFusedStorage;
        add(1 | sat, state.remFusedStorage, -state.remFusedStorage,
                state.remainders[problem.fusedLoop]);
    }
    if (remM)
        min_(1, state.remainders[LoopM], state.remainders[LoopM],
                uint16_t(strategy.unroll[LoopM]));
    if (remN)
        min_(1, state.remainders[LoopN], state.remainders[LoopN],
                uint16_t(strategy.unroll[LoopN]));

    gemmCalcIncrements(problem, strategy, state);

    // Early exit if nothing to do.
    if (earlyExit && (remM || remN)) {
        int simt = problem.fused ? 16 : 1;
        InstructionModifier cond;
        if (remM && remN)
            cond = simt | f0[1] | anyv;
        else if (remM)
            cond = simt | f0[1];
        else
            cond = simt | f1[1];

        problem.fused ? goto12(cond, labelSubkernelDone)
                      : ejmpi(cond, labelSubkernelDone);
    }

    // Create the kernel body. If enabled, create two versions, one with A/B more aligned.
    bool success;
    if (!strategy.optAlignAB)
        success = gemmMEdge(problem, strategy, state);
    else {
        // Check alignment of effA, effB, lda, and ldb.
        Label labelUnaligned;
        uint16_t mask = (strategy.optAlignAB - 1);
        bool check_lda = !isPacked(problem.A.layout);
        bool check_ldb = !isPacked(problem.B.layout);
        if (problem.A.alignment & mask) {
            and_(1 | nz | f0[0], null.uw(), state.effA.uw(), mask);
            if (check_lda)
                and_(1 | nz | f1[0], null.uw(), state.inputs.lda.uw(), mask);
        }
        if (problem.B.alignment & mask) {
            and_(1 | nz | f0[1], null.uw(), state.effB.uw(), mask);
            if (check_ldb)
                and_(1 | nz | f1[1], null.uw(), state.inputs.ldb.uw(), mask);
        }
        if (problem.A.alignment & mask) {
            InstructionModifier amod = check_lda ? 1 | f0[0] | anyv : 1 | f0[0];
            ejmpi(amod, labelUnaligned);
        }
        if (problem.B.alignment & mask) {
            InstructionModifier bmod = check_ldb ? 1 | f0[1] | anyv : 1 | f0[1];
            ejmpi(bmod, labelUnaligned);
        }

        auto alignedProblem = problem;
        alignedProblem.A.setAlignment(
                std::max<int>(problem.A.alignment, strategy.optAlignAB));
        alignedProblem.B.setAlignment(
                std::max<int>(problem.B.alignment, strategy.optAlignAB));

        status << "Aligned A/B" << status_stream::endl;
        success = gemmMEdge(alignedProblem, strategy, state);

        state.isNested ? jmpi(1, labelSubkernelDone)
                       : epilogue(strategy, state);

        mark(labelUnaligned);

        status << "Unaligned A/B" << status_stream::endl;
        if (!gemmMEdge(problem, strategy, state)) {
            auto modStrategy = strategy;

            modStrategy.checkAdd32
                    = false; // Don't optimize additions on this (slow) path to reduce code size.
            status << "Reducing register usage" << status_stream::endl;
            success = success && modStrategy.minimize(hw, problem);

            gemmCalcIncrements(problem, modStrategy,
                    state); // Recalculate lda_ka/ldb_kb as they have changed.

            success = success && gemmMEdge(problem, modStrategy, state);
        }
    }

    if (!success)
        lastException ? std::rethrow_exception(lastException)
                      : throw std::runtime_error("Could not generate kernel.");

    mark(labelSubkernelDone);
    if (earlyExit && problem.fused && (remM || remN)) join(16);

    state.ra.safeRelease(state.ldb_kb);
    state.ra.safeRelease(state.lda_ka);
}

template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmSuperkernelInitState(GEMMProblem &problem,
        GEMMSuperkernelStrategy &strategy, GEMMSuperkernelState &state) {
    gemmInitState(problem, strategy.substrategies[0], state, true);

    state.inputsSK.surfacePlan = interface.getArgumentSurface("plan");
    state.inputsSK.planCount = interface.getArgument("plan_count");
    state.inputsSK.localID = interface.getLocalID(0);
    state.inputsSK.localSize = interface.getLocalSize(0);

    state.ra.claim(state.inputsSK.localID);
    state.ra.claim(state.inputsSK.localSize);
    state.ra.claim(state.inputsSK.planCount);
}

// Create a GEMM superkernel.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::gemmSuperkernel(GEMMProblem problem,
        GEMMSuperkernelStrategy strategy,
        const ngen::NEOInterfaceHandler &interface_, bool loopless) {
    auto Ta = problem.Ta, Tb = problem.Tb, Tc = problem.Tc;
    auto &strategy0 = strategy.substrategies[0];

    GEMMSuperkernelState state(hw);

    // Set up.
    setDefaultNoMask();
    setDefaultAutoSWSB();
    interface = interface_;
    gemmTypeCheck(Ta, Tb, Tc);
    gemmSuperkernelInitState(problem, strategy, state);
    state.ra.safeRelease(state.inputs.localIDN);
    state.ra.safeRelease(state.inputs.localSizeN);
    state.isNested = !loopless;

    if (!problem.A.base.isStateless())
        problem.A.base.setIndex(state.inputs.surfaceA);
    if (!problem.B.base.isStateless())
        problem.B.base.setIndex(state.inputs.surfaceB);
    if (!problem.C.base.isStateless())
        problem.C.base.setIndex(state.inputs.surfaceC[0]);

    // Prevent unhelpful layouts.
    if (problem.A.layout == MatrixLayout::PackedRows) stub();
    if (problem.B.layout == MatrixLayout::PackedColumns) stub();

    Label loopSK, loopSKEnd;

    // Prologue.
    prologue(strategy0);

    // Grab fused ID if needed.
    getFusedID(1, problem, strategy0, state);

    // Get my plan ID and convert to offset in plan.
    auto idX = r0.ud(1);
    auto header = state.ra.alloc();
    auto poff = header.ud(2);
    constexpr uint16_t eltSz = 8;

    if (!problem.wgSupport) {
        cmp<uint32_t>(1 | ge | f0[0], idX, state.inputsSK.planCount);
        mulConstant(1, poff, idX, eltSz);
    } else {
        auto temp = state.ra.alloc_sub<uint32_t>();

        mulConstant(1, temp, state.inputsSK.planCount, strategy.subgroupSize());
        mul(1, poff, idX, state.inputsSK.localSize);
        add(1, poff, poff, state.inputsSK.localID.uw(0));
        cmp<uint32_t>(1 | ge | f0[0], poff, temp);
        if (eltSz < strategy.subgroupSize())
            shr(1, poff, poff, log2(strategy.subgroupSize() / eltSz));
        else if (eltSz > strategy.subgroupSize())
            mulConstant(1, poff, poff, eltSz / strategy.subgroupSize());

        state.ra.safeRelease(temp);
        state.ra.safeRelease(state.inputsSK.localID);
        state.ra.safeRelease(state.inputsSK.localSize);
    }

    if (!loopless) add(1, poff, poff, eltSz);

    // Move r0 to acc0 if configured.
    moveR0(strategy0, state);

    // Quick exit for extra threads (uniform WG).
    jmpi(1 | f0[0], loopSKEnd);

    // Retrieve plan element.
    auto pdata = state.ra.alloc(getHint(HintType::TempComp0, strategy0));
    load(8, pdata, aligned_block_oword(1), Surface(state.inputsSK.surfacePlan),
            header);
    state.ra.safeRelease(header);

    state.i0 = pdata.d(0);
    state.j0 = pdata.d(1);

    state.ra.safeRelease(pdata);
    state.ra.claim(state.i0);
    state.ra.claim(state.j0);

    auto flagKID0 = f1[0];
    auto flagKID1 = f1[1];

    if (strategy.multiM) cmp(1 | lt | flagKID0, null.d(), state.i0, 0);
    if (strategy.multiN) cmp(1 | lt | flagKID1, null.d(), state.j0, 0);
    and_(2, state.i0.ud()(1), state.i0.ud()(1), uint32_t(0x7FFFFFFF));

    // Initial offset of A/B/C.
    gemmOffsetABC(
            true, state.i0, state.j0, Subregister(), problem, strategy0, state);
    gemmSetupABC(problem, strategy0, state);

    // Save i0, j0 for later.
    state.last_i0 = state.ra.alloc_sub<int32_t>(
            getHint(HintType::LongTerm, strategy0));
    state.last_j0 = state.ra.alloc_sub<int32_t>(
            getHint(HintType::LongTerm, strategy0));
    mov(1, state.last_i0, state.i0);
    mov(1, state.last_j0, state.j0);

    // Top of superkernel loop.
    status << "Begin superkernel loop" << status_stream::endl;
    mark(loopSK);
    {
        // Dispatch appropriate kernel, supporting up to 4 subkernels.
        int kidx = 0;
        Label labelM1, labelM0N1, labelM1N1, labelKernelDone;
        if (strategy.multiM) jmpi(1 | flagKID0, labelM1);
        if (strategy.multiN) jmpi(1 | flagKID1, labelM0N1);

        gemmSubkernel(problem, strategy.substrategies[kidx++], state);

        if (strategy.multiN) {
            jmpi(1, labelKernelDone);
            mark(labelM0N1);
            gemmSubkernel(problem, strategy.substrategies[kidx++], state);
        }

        if (strategy.multiM) {
            jmpi(1, labelKernelDone);

            mark(labelM1);
            if (strategy.multiN) jmpi(1 | flagKID1, labelM1N1);

            gemmSubkernel(problem, strategy.substrategies[kidx++], state);

            if (strategy.multiN) {
                jmpi(1, labelKernelDone);
                mark(labelM1N1);
                gemmSubkernel(problem, strategy.substrategies[kidx++], state);
            }
        }

        mark(labelKernelDone);

        if (!loopless) {
            // Get next plan element via atomic increment of plan ID counter.
            auto header = state.ra.alloc();
            auto nextID
                    = state.ra.alloc(getHint(HintType::TempComp1, strategy0));
            auto pdata
                    = state.ra.alloc(getHint(HintType::TempComp0, strategy0));

            mov<uint32_t>(8, header, uint16_t(0));
            atomic(AtomicOp::inc, 1, nextID, scattered_dword(),
                    Surface(state.inputsSK.surfacePlan), header);

            // Load next plan element, or exit if no more work.
            mulConstant<uint32_t>(1, header[2], nextID[0], eltSz);
            cmp<uint32_t>(
                    1 | ge | f0[0], null, nextID[0], state.inputsSK.planCount);
            add<uint32_t>(1, header[2], header[2], eltSz);

            jmpi(1 | f0[0], loopSKEnd);

            load(8, pdata, aligned_block_oword(1),
                    Surface(state.inputsSK.surfacePlan), header);
            state.ra.safeRelease(header);
            state.ra.safeRelease(nextID);

            // Load next (i0, j0) and kernel IDs.
            auto in_i0 = pdata.d(0);
            auto in_j0 = pdata.d(1);

            if (strategy.multiM) cmp(1 | lt | flagKID0, null.d(), in_i0, 0);
            if (strategy.multiN) cmp(1 | lt | flagKID1, null.d(), in_j0, 0);
            and_(1, state.i0.ud(), in_i0.ud(), uint32_t(0x7FFFFFFF));
            and_(1, state.j0.ud(), in_j0.ud(), uint32_t(0x7FFFFFFF));

            // Get difference in i0 and j0...
            add(1, in_i0, state.i0, -state.last_i0);
            add(1, in_j0, state.j0, -state.last_j0);

            // ... save current (i0, j0) for later...
            mov(1, state.last_i0, state.i0);
            mov(1, state.last_j0, state.j0);

            // ...and offset A, B, C appropriately.
            gemmOffsetABC(false, in_i0, in_j0, Subregister(), problem,
                    strategy0, state);

            state.ra.safeRelease(pdata);

            state.ra.safeRelease(state.i0);
            state.ra.safeRelease(state.j0);

            // Ready for the next kernel.
            jmpi(1, loopSK);
        }
    }
    mark(loopSKEnd);

    epilogue(strategy.substrategies[0], state);
    padding();
}

// Check for a supported combination of A/B/C types.
template <HW hw>
void gemm_kernel_generator_t<hw>::gemmTypeCheck(Type Ta, Type Tb, Type Tc) {}

// Get driver information from this strategy.
CommonDriverInfo GEMMStrategy::driverInfo(const GEMMProblem &problem) const {
    CommonDriverInfo info;

    info.subgroupSize = subgroupSize;
    info.fusedEUs = problem.fused;
    for (int d = 0; d < 3; d++) {
        info.loopOrder[d] = loopOrder[d];
        info.blocking[d] = blocking[d];
        info.unroll[d] = unroll[d];
        info.wg[d] = wg[d];
    }
    info.fixedWG = slmA || slmB;
    info.kRemainderHandling = (remHandling[LoopK] != RemainderHandling::Ignore);
    info.kBlocking = kBlocking;
    if (problem.batch == BatchMode::None) info.loopOrder[2] = LoopNone;

    return info;
}

// Return the maximum possible k size for copied SLM data.
int GEMMStrategy::maxKSLM(const GEMMState &state, bool isA) const {
    return unrollKSLM;
}

// Perform a sanity check on a GEMM strategy, correcting settings as necessary.
void GEMMStrategy::sanityCheck(HW hw, const GEMMProblem &problem) {
    auto Ta_real = problem.Ta.real();
    auto Tb_real = problem.Tb.real();
    auto Tc_real = problem.Tc.real();

    duplicateA &= !doubleWA;
    duplicateB &= !doubleWA;

    // Accumulator usage: 64-bit emulation, or extra C registers, or storage for r0 header.
    bool emulateNeedsAcc = emulate.emulate64 || emulate.emulateDWxDW;
    cAccumulators &= !emulateNeedsAcc;
    if (moveR0 == MoveR0::Acc)
        if (cAccumulators || emulateNeedsAcc || xParallel)
            moveR0 = MoveR0::None;

    // Mixed mode restrictions:
    //   mixed hf/f is max SIMD 8 on Gen9
    //   mixed hf/f is not allowed on Xe
    if ((Tc_real == Type::f32)
            && (Ta_real != Type::f32 || Tb_real != Type::f32))
        fmaSIMD = std::min(fmaSIMD, GRF::bytes(hw) >> 2);

    // No jump table paths use SIMT control flow. Also atomic reductions.
    spf &= !noJumpTables;
    spf &= !C.atomic;

    checkAdd32 &= !emulate.emulate64_add32;

    // SLM copy logic.
    int ukAlign = 1;
    if (slmBuffers > 0) {
        moveR0 = MoveR0::None;
        barrierFreq = 0;
        if (wg[LoopM] <= 0 || wg[LoopN] <= 0)
            throw std::runtime_error("Workgroup sizes required.");
        if (slmA) ukAlign = lcm(ukAlign, wg[LoopN] * slmCopies);
        if (slmB) ukAlign = lcm(ukAlign, wg[LoopM] * slmCopies);
    }

    // Always use 1D addressing for packed inputs.
    A.address2D &= !isPacked(problem.A.layout);
    B.address2D &= !isPacked(problem.B.layout);

    // k unroll wrangling.
    if (ka_repack) ka_repack = gcd(ka_repack, ka_load);
    if (kb_repack) kb_repack = gcd(kb_repack, kb_load);
    ukAlign = lcm(ukAlign, ka_load);
    ukAlign = lcm(ukAlign, kb_load);
    unroll[LoopK] = align_up(unroll[LoopK], lcm(A_copies, B_copies) * ukAlign);
    barrierFreq = align_up(barrierFreq, unroll[LoopK]);

    slmA &= (slmBuffers > 0);
    slmB &= (slmBuffers > 0);

    unrollKSLM = unroll[LoopK] / slmCopies;

    // Default blocking.
    bool isZ = problem.Tc.size() >= 16;
    if (blocking[LoopM] <= 0) blocking[LoopM] = isZ ? 2048 : 4096;
    if (blocking[LoopN] <= 0) blocking[LoopN] = isZ ? 2048 : 4096;
    if (blocking[LoopK] <= 0) {
        int points = 1;
        if (slmA || (problem.A.layout != MatrixLayout::T)) points++;
        if (slmB || (problem.B.layout != MatrixLayout::N)) points++;
        blocking[LoopK] = std::min(2048, (2048 * points) / problem.Ta);
    }

    // Default workgroups.
    auto defaultWGX = 2, defaultWGY = 8;

    if (wg[loopOrder[0]] <= 0) wg[loopOrder[0]] = defaultWGX;
    if (wg[loopOrder[1]] <= 0) wg[loopOrder[1]] = defaultWGY;

    CommonStrategy::sanityCheck(hw, problem);
}

// Reduce register pressure. Returns true if successful.
bool GEMMStrategy::minimize(HW hw, const GEMMProblem &problem) {
    bool better = false;
    auto opCount = outerProductCount(hw, problem, *this);
    auto ka_load_best_min = std::max<int>({1, 4 / problem.Ta, opCount});
    auto kb_load_best_min = std::max<int>({1, 4 / problem.Tb, opCount});

    // Reduce ka/b_load down to suggested minimums (not requiring crosspack)
    if (ka_load > ka_load_best_min) {
        ka_load = ka_load_best_min;
        if (ka_repack > ka_load) ka_repack = ka_load;
        better = true;
    }
    if (kb_load > kb_load_best_min) {
        kb_load = kb_load_best_min;
        if (kb_repack > kb_load) kb_repack = kb_load;
        better = true;
    }

    // Reduce A/B copies.
    A_copies = B_copies = 1;

    // Reduce k unroll for SLM copies.
    if (slmA || slmB) {
        auto oldUK = unroll[LoopK];
        unroll[LoopK] = 1;
        sanityCheck(hw, problem);
        better |= (unroll[LoopK] < oldUK);
    }

    if (better) return better;

    // Reduce ka/b_load to absolute minimum if that failed.
    if (ka_load > opCount) {
        ka_load = opCount;
        if (ka_repack > ka_load) ka_repack = ka_load;
        better = true;
    }
    if (kb_load > opCount) {
        kb_load = opCount;
        if (kb_repack > kb_load) kb_repack = kb_load;
        better = true;
    }

    return better;
}

// Perform a sanity check on a GEMM superkernel strategy, correcting settings as necessary.
void GEMMSuperkernelStrategy::sanityCheck(
        ngen::HW hw, const GEMMProblem &problem) {
    if (substrategies.size() <= 0)
        throw std::runtime_error("No substrategies for superkernel.");
    auto subgroupSize = substrategies[0].subgroupSize;
    for (auto &ss : substrategies) {
        ss.insideSK = true;
        ss.sanityCheck(hw, problem);
        if (ss.subgroupSize != subgroupSize)
            throw std::runtime_error("Incompatible subgroup sizes.");
    }
}

/**********************************************************************/
/*                             Copy Kernels                           */
/**********************************************************************/

// Initialize the state structure.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::copyInitState(
        CopyProblem &problem, CopyStrategy &strategy, CopyState &state) {
    initState(problem, strategy, state);

    if (strategy.barrierFreq > 0) interface.requireBarrier();

    interface.finalize();

    // Get input register assignments.
    state.inputs.S = interface.getArgument("S");
    state.inputs.D = interface.getArgument("D");
    state.inputs.surfaceS = interface.getArgumentSurface("S");
    state.inputs.surfaceD = interface.getArgumentSurface("D");
    state.inputs.offsetS = interface.getArgument("offset_S");
    state.inputs.offsetD = interface.getArgument("offset_D");
    state.inputs.lds = interface.getArgument("lds");
    state.inputs.ldd = interface.getArgumentIfExists("ldd");
    state.inputs.m = interface.getArgument("m");
    state.inputs.n = interface.getArgument("n");
    state.inputs.alpha_real = interface.getArgumentIfExists("alpha_real");
    state.inputs.alpha_imag = interface.getArgumentIfExists("alpha_imag");
    state.inputs.diag = interface.getArgumentIfExists("diag");
    state.inputs.blockZ = interface.getArgumentIfExists("block_z");

    if (problem.wgSupport) {
        state.inputs.localIDW = interface.getLocalID(0);
        state.inputs.localSizeW = interface.getLocalSize(0);
        if (strategy.zBlocking) {
            state.inputs.localIDZ = interface.getLocalID(1);
            state.inputs.localSizeZ = interface.getLocalSize(1);
        }
    }

    state.inputs.groupIDW = r0.ud(1);
    if (strategy.zBlocking) state.inputs.groupIDZ = r0.ud(6);

    // Downgrade offset variables to 32-bit for non-A64 accesses.
    if (problem.S.base.getModel() != ModelA64)
        state.inputs.offsetS = state.inputs.offsetS.d();
    if (problem.D.base.getModel() != ModelA64)
        state.inputs.offsetD = state.inputs.offsetD.d();

    // For now, reinterpret m/n/ld/diag variables to 32-bit if they are 64-bit.
    state.inputs.m = state.inputs.m.d();
    state.inputs.n = state.inputs.n.d();
    state.inputs.lds = state.inputs.lds.ud();
    if (state.inputs.ldd.isValid()) state.inputs.ldd = state.inputs.ldd.ud();
    if (state.inputs.diag.isValid()) state.inputs.diag = state.inputs.diag.d();

    // Claim inputs.
    for (int i = 0; i < 4; i++)
        state.ra.claim(r0.uq(i));

    if (problem.S.base.isStateless()) {
        state.effS = state.inputs.S;
        state.ra.claim(state.inputs.S);
    } else
        state.effS = state.inputs.offsetS.d();

    if (problem.D.base.isStateless()) {
        state.effD = state.inputs.D;
        state.ra.claim(state.inputs.D);
    } else
        state.effD = state.inputs.offsetD.d();

    state.ra.claim(state.inputs.offsetS);
    state.ra.claim(state.inputs.offsetD);
    state.ra.claim(state.inputs.lds);
    if (state.inputs.ldd.isValid()) state.ra.claim(state.inputs.ldd);
    state.ra.claim(state.inputs.m);
    state.ra.claim(state.inputs.n);
    if (state.inputs.diag.isValid()) state.ra.claim(state.inputs.diag);

    if (!problem.alpha_real.fixed()) {
        state.ra.claim(state.inputs.alpha_real);
        problem.alpha_real = state.inputs.alpha_real;
    }

    if (problem.Td.isComplex() && !problem.alpha_imag.fixed()) {
        state.ra.claim(state.inputs.alpha_imag);
        problem.alpha_imag = state.inputs.alpha_imag;
    }

    if (problem.wgSupport) {
        state.ra.claim(state.inputs.localIDW);
        state.ra.claim(state.inputs.localSizeW);
        if (strategy.zBlocking) {
            state.ra.claim(state.inputs.localIDZ);
            state.ra.claim(state.inputs.localSizeZ);
        }
    }

    if (strategy.zBlocking) state.ra.claim(state.inputs.blockZ);

    state.isNested = false;
    state.flagAP = state.raVFlag.alloc();

    state.allocEmulate64Temp(strategy.emulate);
}

// Copy kernel generation interface.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::copy(CopyProblem problem,
        CopyStrategy strategy, const NEOInterfaceHandler &interface_) {
    CopyState state(hw);

    // Check layouts.
    if (!isPacked(problem.D.layout)) stub();

    // By default, don't use dispatch mask.
    setDefaultNoMask();
    setDefaultAutoSWSB();

    // Set up.
    interface = interface_;
    copyInitState(problem, strategy, state);

    if (!problem.S.base.isStateless())
        problem.S.base.setIndex(state.inputs.surfaceS);
    if (!problem.D.base.isStateless())
        problem.D.base.setIndex(state.inputs.surfaceD);

    prologue(strategy);

    // Grab fused ID if needed.
    auto unrollW = strategy.unrollW();
    getFusedID(unrollW, problem, strategy, state);

    // Calculate w0, the starting row/column for this thread.
    // This is the first x (if xloop = false) or y (xloop = true) value.
    state.w0 = state.ra.alloc_sub<uint32_t>(
            getHint(HintType::TempComp0, strategy));
    if (strategy.zBlocking)
        state.z0 = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp1, strategy));

    if (problem.wgSupport) {
        auto globalIDW = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp1, strategy));
        auto globalIDZ = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));

        bool multiple = (unrollW % strategy.subgroupSize) == 0;

        mul(1, globalIDW, state.inputs.groupIDW, state.inputs.localSizeW.uw());
        if (strategy.zBlocking)
            mul(1, globalIDZ, state.inputs.groupIDZ,
                    state.inputs.localSizeZ.uw());
        add(1, globalIDW, globalIDW, state.inputs.localIDW.uw(0));
        if (strategy.zBlocking)
            add(1, globalIDZ, globalIDZ, state.inputs.localIDZ.uw(0));
        if (multiple)
            mulConstant(
                    1, state.w0, globalIDW, unrollW / strategy.subgroupSize);
        else {
            mulConstant(1, state.w0, globalIDW, unrollW);
            shr(1, state.w0, state.w0, log2(strategy.subgroupSize));
        }
        if (strategy.zBlocking)
            emul(1, state.z0, globalIDZ, state.inputs.blockZ, strategy, state);

        state.ra.safeRelease(globalIDW);
        state.ra.safeRelease(globalIDZ);
        state.ra.safeRelease(state.inputs.localIDW);
        state.ra.safeRelease(state.inputs.localIDZ);
        state.ra.safeRelease(state.inputs.localSizeW);
        state.ra.safeRelease(state.inputs.localSizeZ);
    } else {
        mulConstant(1, state.w0, state.inputs.groupIDW, unrollW);
        if (strategy.zBlocking)
            emul(1, state.z0, state.inputs.groupIDZ, state.inputs.blockZ,
                    strategy, state);
    }

    // Move r0 to acc0 if configured.
    moveR0(strategy, state);

    // Copy our slice.
    copySlice(problem, strategy, state);

    epilogue(strategy, state);

    padding();
}

// Calculate or recalculate lds_sl/ldd_dl as needed.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::copyCalcIncrements(const CopyProblem &problem,
        const CopyStrategy &strategy, CopyState &state, int s_load,
        int d_load) {
    // S: w0 * s_load is needed for N->Pc, T->Pr [!xLoop] N->Pr, T->Pc [xLoop]
    // D: no increment needed (always packed)    [!xLoop] ldd * d_load [xLoop]
    bool sStrided
            = (isColMajor(problem.S.layout) == isColMajor(problem.D.layout))
            ^ strategy.xLoop;

    if (sStrided || problem.reflecting()) {
        if (s_load == 0) s_load = strategy.s_load;
        if (s_load > 1) {
            if (state.lds_sl.isInvalid()) {
                state.lds_sl = state.ra.alloc_sub<uint32_t>();
                s_load *= problem.Ts.size();
            }
            emulConstant(
                    1, state.lds_sl, state.inputs.lds, s_load, strategy, state);
        }
    }

    if (strategy.xLoop) {
        if (d_load == 0) d_load = strategy.d_load;
        if (d_load > 1) {
            if (state.ldd_dl.isInvalid()) {
                state.ldd_dl = state.ra.alloc_sub<uint32_t>();
                d_load *= problem.Td.size();
            }
            emulConstant(
                    1, state.ldd_dl, state.inputs.ldd, d_load, strategy, state);
        }
    }
}

// Copy kernel generation interface.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::copySlice(
        CopyProblem &problem, CopyStrategy &strategy, CopyState &state) {
    auto Ts = problem.Ts, Td = problem.Td;
    Label labelExit;
    Subregister lddSrc;

    // If ldd not specified, use y.
    if (state.inputs.ldd.isInvalid()) {
        state.inputs.ldd = lddSrc = (problem.D.layout == MatrixLayout::Pc)
                ? state.inputs.n
                : state.inputs.m;
        if (problem.D.crosspack > 1 || problem.sum) {
            state.inputs.ldd = state.ra.alloc_sub<uint32_t>(
                    getHint(HintType::LongTerm, strategy));
            mov(1, state.inputs.ldd, lddSrc);
            lddSrc = invalid;
        }
        if (problem.D.crosspack > 1) {
            add(1, state.inputs.ldd, state.inputs.ldd, problem.D.crosspack - 1);
            and_(1, state.inputs.ldd, state.inputs.ldd,
                    ~uint32_t(problem.D.crosspack - 1));
        }
        if (problem.sum)
            add(1, state.inputs.ldd, state.inputs.ldd,
                    problem.Tsum.size() / problem.Td.size());
    }

    // Duplicate alpha if configured.
    if (strategy.duplicateAlpha) { duplicateScalar(problem.alpha_real, state); }

    // For fused kernels, compute 2 * unrollW - fusedID for use in several places.
    Subregister unrollWRem;
    if (problem.fused) {
        unrollWRem = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));
        add(1, unrollWRem, -state.fusedID, uint16_t(2 * strategy.unrollW()));
    }

    // Align code paths.
    bool mLoop = isColMajor(problem.D.layout) == strategy.xLoop;
    auto z = mLoop ? state.inputs.m : state.inputs.n;
    Subregister z0;

    // Handle z blocking.
    if (strategy.zBlocking) {
        z0 = state.z0;
        add(1 | le | f0[1], z, z, -z0);
        min_(1, z, z, state.inputs.blockZ);
        state.ra.safeRelease(state.inputs.blockZ);
    }

    // Compute base addresses for S, D.
    //   S += w0 + z0 * lds (N->Pc, T->Pr) z0 + w0 * lds (N->Pr, T->Pc) [swapped if xLoop = true]
    bool sStrided
            = (isColMajor(problem.S.layout) == isColMajor(problem.D.layout))
            ^ strategy.xLoop;
    auto incC = sStrided ? state.w0 : z0;
    auto incS = sStrided ? z0 : state.w0;

    if (incC.isValid())
        eadd(1, state.inputs.offsetS, state.inputs.offsetS, incC, strategy,
                state);
    if (incS.isValid()) {
        Subregister temp = state.ra.alloc_sub(state.inputs.offsetS.getType(),
                getHint(HintType::TempComp1, strategy));
        emul(1, temp, incS, state.inputs.lds, strategy, state);
        eadd(1, state.inputs.offsetS, state.inputs.offsetS, temp, strategy,
                state);
        state.ra.safeRelease(temp);
    }

    // Quick exit if no work to do.
    if (strategy.zBlocking) jmpi(1 | f0[1], labelExit);

    // D += align_up(x0, unroll) * ldd + y0 * unroll + (x0 % unroll) * crosspack
    {
        Subregister temp0 = state.ra.alloc_sub(state.inputs.offsetD.getType(),
                getHint(HintType::TempComp0, strategy));
        Subregister temp1 = state.ra.alloc_sub(state.inputs.offsetD.getType(),
                getHint(HintType::TempComp1, strategy));
        Subregister temp2 = state.ra.alloc_sub<uint32_t>(
                getHint(HintType::TempComp0, strategy));
        auto x0 = strategy.xLoop ? z0 : state.w0;
        auto y0 = strategy.xLoop ? state.w0 : z0;
        bool splitX = strategy.unrollX < problem.D.packSize;

        if (x0.isValid()) {
            if (splitX) {
                modExt(temp2, temp1.ud(), x0, problem.D.packSize, strategy,
                        state);
                emul(1, temp0, temp1.ud(), state.inputs.ldd, strategy, state);
                mulConstant(1, temp2, temp2, problem.D.crosspack);
            } else
                emul(1, temp0, x0, state.inputs.ldd, strategy, state);
        }
        if (y0.isValid())
            emulConstant(1, temp1, y0, problem.D.packSize, strategy, state);
        if (x0.isValid())
            eadd(1, state.inputs.offsetD, state.inputs.offsetD, temp0, strategy,
                    state);
        if (y0.isValid())
            eadd(1, state.inputs.offsetD, state.inputs.offsetD, temp1, strategy,
                    state);
        if (x0.isValid() && splitX)
            eadd(1, state.inputs.offsetD, state.inputs.offsetD, temp2, strategy,
                    state);

        state.ra.safeRelease(temp0);
        state.ra.safeRelease(temp1);
        state.ra.safeRelease(temp2);
    }

    state.ra.safeRelease(z0);
    state.z0 = invalid;

    // Calculate increments.
    copyCalcIncrements(problem, strategy, state);

    // Calculate remainders for w loop as needed.
    if (!strategy.xLoop
            && (strategy.remHandlingX != RemainderHandling::Ignore)) {
        auto x = (problem.D.layout == MatrixLayout::Pc) ? state.inputs.m
                                                        : state.inputs.n;
        state.remainderX = state.ra.alloc_sub<uint32_t>();
        add(1 | sat, state.remainderX, -state.w0, x);
        if (strategy.remHandlingX == RemainderHandling::Split) {
            if (problem.fused)
                cmp(1 | lt | state.flagAP, null.ud(), state.remainderX,
                        unrollWRem);
            else
                cmp(1 | lt | state.flagAP, null.ud(), state.remainderX,
                        strategy.unrollX);
            mov(1 | ~state.flagAP, state.remainderX, strategy.unrollX);
        } else
            min_(1, state.remainderX, state.remainderX, strategy.unrollX);
    }
    if (strategy.xLoop
            && (strategy.remHandlingY != RemainderHandling::Ignore)) {
        auto y = (problem.D.layout == MatrixLayout::Pc) ? state.inputs.n
                                                        : state.inputs.m;
        state.remainderY = state.ra.alloc_sub<uint32_t>();
        add(1 | sat, state.remainderY, -state.w0, y);
        if (strategy.remHandlingY == RemainderHandling::Split) {
            if (problem.fused)
                cmp(1 | lt | state.flagAP, null.ud(), state.remainderY,
                        unrollWRem);
            else
                cmp(1 | lt | state.flagAP, null.ud(), state.remainderY,
                        strategy.unrollY);
            mov(1 | ~state.flagAP, state.remainderY, strategy.unrollY);
        } else
            min_(1, state.remainderY, state.remainderY, strategy.unrollY);
    }

    // Convert lds to bytes.
    emulConstant(
            1, state.inputs.lds, state.inputs.lds, Ts.size(), strategy, state);

    // Add offsets to base pointers for stateless accesses.
    emulConstant(1, state.inputs.offsetS, state.inputs.offsetS, Ts.size(),
            strategy, state);
    emulConstant(1, state.inputs.offsetD, state.inputs.offsetD, Td.size(),
            strategy, state);

    if (problem.S.base.isStateless()) {
        eadd(1, state.inputs.S, state.inputs.S, state.inputs.offsetS, strategy,
                state);

        state.ra.safeRelease(state.inputs.offsetS);
    } else
        state.effS1 = state.offsetS1;

    if (problem.D.base.isStateless()) {
        eadd(1, state.inputs.D, state.inputs.D, state.inputs.offsetD, strategy,
                state);
        state.ra.safeRelease(state.inputs.offsetD);
    }

    state.ra.safeRelease(unrollWRem);

    if (!copyBody(problem, strategy, state)) {
        lastException ? std::rethrow_exception(lastException)
                      : throw std::runtime_error("Could not generate kernel.");
    }

    mark(labelExit);
}

// Wrapper around copyBodyRemCheck, checking for optimally-aligned S.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyBody(
        CopyProblem &problem, CopyStrategy &strategy, CopyState &state) {
    if (!is_zero_or_pow2(strategy.optionalAlignS)) stub();

    bool success;

    if (strategy.optionalAlignS == 0)
        success = copyBodyRemCheck(problem, strategy, state);
    else {
        Label labelUnaligned, labelEnd;

        status << "S alignment check" << status_stream::endl;
        and_(1 | nz | f0[1], null.uw(), state.effS.uw(),
                uint16_t(strategy.optionalAlignS - 1));
        and_(1 | nz | f1[1], null.uw(), state.inputs.lds.uw(),
                uint16_t(strategy.optionalAlignS - 1));
        ejmpi(1 | f0[1] | anyv, labelUnaligned);

        auto modProblem = problem;
        modProblem.S.setAlignment(strategy.optionalAlignS);

        status << "S aligned to " << strategy.optionalAlignS << ':'
               << status_stream::endl;
        success = copyBodyRemCheck(modProblem, strategy, state);

        if (state.isNested)
            jmpi(1, labelEnd);
        else
            epilogue(strategy, state);

        mark(labelUnaligned);

        status << "S unaligned" << status_stream::endl;
        success = success && copyBodyRemCheck(problem, strategy, state);

        mark(labelEnd);
    }

    return success;
}

// Wrapper around copyBodyInternal, handling split remainders.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyBodyRemCheck(
        CopyProblem &problem, CopyStrategy &strategy, CopyState &state) {
    auto CopyStrategy::*remHandlingW
            = (strategy.xLoop ? &CopyStrategy::remHandlingY
                              : &CopyStrategy::remHandlingX);
    bool wSplit = strategy.*remHandlingW == RemainderHandling::Split;
    bool success;

    if (!wSplit)
        success = copyBodyInternal(problem, strategy, state);
    else {
        CopyStrategy modStrategy = strategy;
        Label wRemBegin, wRemEnd;
        jmpi(1 | state.flagAP, wRemBegin);

        status << "Generating "
               << "xy"[strategy.xLoop] << " non-remainder kernel"
               << status_stream::endl;
        modStrategy.*remHandlingW = RemainderHandling::Ignore;
        success = copyBodyInternal(problem, modStrategy, state);

        if (state.isNested)
            jmpi(1, wRemEnd);
        else
            epilogue(strategy, state);

        modStrategy.*remHandlingW = RemainderHandling::KnownRemainder;

        bool recalc = false;

        if (strategy.xLoop && !isTransposing(modStrategy.D.accessType)) {
            // Change D access to use scattered stores so masking is possible.
            modStrategy.D.accessType = AccessType::Scattered;
            modStrategy.S.accessType = isTransposing(modStrategy.S.accessType)
                    ? AccessType::Block
                    : AccessType::Scattered;
        }
        if (!strategy.xLoop && !problem.S.padded) {
            // Check if we need to change s_load/d_load.
            if (strategy.s_load > strategy.s_load_masked) {
                status << "Downgrading s_load: " << strategy.s_load << " -> "
                       << strategy.s_load_masked << status_stream::endl;
                modStrategy.s_load = strategy.s_load_masked;
                recalc = true;
            }
            if (strategy.d_load > strategy.d_load_masked) {
                status << "Downgrading d_load: " << strategy.d_load << " -> "
                       << strategy.d_load_masked << status_stream::endl;
                modStrategy.d_load = strategy.d_load_masked;
                recalc = true;
            }
        }

        status << "Generating "
               << "xy"[strategy.xLoop] << " remainder kernel"
               << status_stream::endl;
        mark(wRemBegin);
        if (recalc) copyCalcIncrements(problem, modStrategy, state);
        success = success && copyBodyInternal(problem, modStrategy, state);
        mark(wRemEnd);
    }

    return success;
}

// Body of copy kernel.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyBodyInternal(
        CopyProblem &problem, CopyStrategy &strategy, CopyState &state) {
    Label lZLoopBegin, lZLoopEnd;
    constexpr auto SD_copies = 1;
    vector<MaskAssignment> masks;
    bool share;

    auto Ts = problem.Ts, Td = problem.Td, Tsum = problem.Tsum;
    const bool byColumn = isColMajor(problem.D.layout);
    const bool sStrided
            = (isColMajor(problem.S.layout) == isColMajor(problem.D.layout))
            ^ strategy.xLoop;
    const bool mLoop = isColMajor(problem.D.layout) == strategy.xLoop;

    const bool reflecting = false;
    const bool triRemOnly = false;

    auto crosspack = problem.D.crosspack;

    // Release w0 -- no longer needed.
    state.ra.safeRelease(state.w0);

    MatrixAddressingStrategy S_strategyReflected = strategy.S;
    vector<RegisterBlock> S_layoutReflected;

    // Decide what remainder handling needs to be done.
    bool remainderX = (strategy.remHandlingX != RemainderHandling::Ignore);
    bool remainderY = (strategy.remHandlingY != RemainderHandling::Ignore);
    bool remainderZ = strategy.xLoop ? remainderX : remainderY;

    bool checkYRem1 = strategy.xLoop && remainderY && strategy.unrollY == 1;
    VirtualFlag flagYRem1;

    remainderY &= !checkYRem1;

    // Get register layouts for S and D.
    int nms, nmd, nns, nnd;
    auto setup = [&](int s_load, int d_load, Subregister S_addr0,
                         Subregister S1_addr0, Subregister D_addr0,
                         bool handleRemZ) -> bool {
        bool remM = remainderX && (!strategy.xLoop || handleRemZ);
        bool remN = remainderY && (strategy.xLoop || handleRemZ);
        Subregister remainders[3]
                = {state.remainderX, state.remainderY, Subregister {}};

        if (!strategy.xLoop) {
            nmd = nms = strategy.unrollX;
            nnd = d_load;
            nns = s_load;
        } else {
            nnd = nns = strategy.unrollY;
            nmd = d_load;
            nms = s_load;
        }

        if (!byColumn) {
            std::swap(nms, nns);
            std::swap(nmd, nnd);
            std::swap(remM, remN);
            std::swap(remainders[0], remainders[1]);
        }

        auto remM_S = remM && !problem.S.padded;
        auto remN_S = remN && !problem.S.padded;
        auto remM_D = remM && !problem.D.padded && !byColumn;
        auto remN_D = remN && !problem.D.padded && byColumn;

        auto sMaxRBlock = 0;
        auto sMaxCBlock = 0;

        if (!getRegLayout(Ts, state.S_layout, nms, nns, remM_S, remN_S, false,
                    true, ScatterSIMD::Default, sMaxRBlock, sMaxCBlock,
                    problem.S, strategy.S))
            return false;
        if (!getRegLayout(Td, state.D_layout, nmd, nnd, remM_D, remN_D, true,
                    true, ScatterSIMD::Default, 0, 0, problem.D, strategy.D))
            return false;

        if (hasFragmenting(state.S_layout) || hasFragmenting(state.D_layout)) {
            status << "Fragmenting not supported." << status_stream::endl;
            return false;
        }

        bool success = true;
        if (checkYRem1) {
            flagYRem1 = state.raVFlag.allocVirtual();
            success &= !(state.raVFlag.isVirtual(flagYRem1)
                    && state.vflagStorage.isInvalid());
        }

        // Find and load any needed mask registers.
        success = success
                && assignMasks(state.S_layout, LoopM, LoopN, masks, state)
                && assignMasks(state.D_layout, LoopM, LoopN, masks, state);

        if (!success && state.vflagStorage.isInvalid()) {
            status << "Retrying with virtual flags." << status_stream::endl;
            allocVFlagStorage(strategy, state);
            success = assignMasks(state.S_layout, LoopM, LoopN, masks, state)
                    && assignMasks(state.D_layout, LoopM, LoopN, masks, state);
        }

        if (!success) return false;

        loadMasks(masks, remainders, state);

        if (!strategy.xLoop && !remM_D && !remN_D
                && strategy.remHandlingX != RemainderHandling::Ignore) {
            // Find a mask to use for destination layout for y loop remainders.
            VirtualFlag flag;
            bool found = false;
            for (auto &mask : masks)
                if (mask.var == (byColumn ? LoopM : LoopN) && mask.offset == 0)
                    flag = mask.flag, found = true;
            if (!found) stub();
            for (auto &block : state.D_layout) {
                block.flag = flag;
                block.flagAny = true;
            }
        } else if (checkYRem1) {
            // Create mask for y remainder for x-loop kernels with unrollY == 1, and
            // apply it by hand to both source and destination.
            RegData regYRem1 = getMaskFlag(flagYRem1, state);
            FlagRegister testFlag;

            testFlag = regYRem1.isARF()
                    ? reinterpret_cast<FlagRegister &>(regYRem1)
                    : f0[1];

            cmp(16 | gt | testFlag, state.remainderY, 0);

            for (auto &mask : masks)
                mov(1 | ~testFlag, getMaskFlag(mask.flag, state), 0);
            if (!regYRem1.isARF()) mov(1, regYRem1, testFlag);

            for (auto &block : state.S_layout)
                if (!block.flag) block.flag = flagYRem1;
            for (auto &block : state.D_layout) {
                block.flag = flagYRem1;
            }
        }

        // Match source layout to destination layout if possible, so that they can share registers.
        share = (Ts == Td) && (s_load == d_load)
                && matchLayouts(Ts, state.S_layout, state.D_layout);

        // Allocate address registers.
        allocAddrRegs(state.S_addrs, state.S_layout, problem.S, strategy.S,
                state,
                getHint(share ? HintType::DAddr : HintType::SAddr, strategy));
        allocAddrRegs(state.D_addrs, state.D_layout, problem.D, strategy.D,
                state, getHint(HintType::DAddr, strategy));

        // Set up address registers.
        setupAddr(Ts, state.S_addrs, S_addr0, state.S_layout, state.inputs.lds,
                problem.S, strategy.S, strategy, state);
        setupAddr(Td, state.D_addrs, D_addr0, state.D_layout, state.inputs.ldd,
                problem.D, strategy.D, strategy, state);

        // Allocate data registers.
        int S_regCount = getRegCount(state.S_layout);
        int D_regCount = getRegCount(state.D_layout);

        state.D_regs = state.ra.alloc_range(
                D_regCount, getHint(HintType::D, strategy));
        state.S_regs = share ? state.D_regs
                             : state.ra.alloc_range(S_regCount,
                                     getHint(HintType::S, strategy));

        // Prepare for summation.
        // Clean up previous sums if any, and try to reuse their registers.
        // Allocate and zero new sum registers as needed.
        if (problem.sum) {
            if (strategy.xLoop) stub();

            vector<RegisterBlock> Ds_layout;
            makeSumLayout(!byColumn, Td, state.D_layout, Tsum, Ds_layout,
                    strategy, state);

            bool alloc = state.Ds_layout.empty()
                    || !matchLayouts(Tsum, Ds_layout, state.Ds_layout);
            if (!state.Ds_layout.empty() && alloc) {
                horizontalAdd(
                        !byColumn, Tsum, state.Ds_regs.back(), state.Ds_layout);
                alloc = !matchLayouts(Tsum, Ds_layout, state.Ds_layout);
            }
            if (alloc) {
                state.Ds_layout = std::move(Ds_layout);
                auto Ds_regs
                        = state.ra.alloc_range(getRegCount(state.Ds_layout));
                zeroMatrix(Ds_regs, strategy);
                state.Ds_regs.push_back(Ds_regs);
            }
        }

        return true;
    };

    auto cleanup = [&]() {
        state.raVFlag.safeRelease(flagYRem1);
        releaseMaskAssignments(masks, state);
        safeReleaseRanges(state.S_addrs, state);
        safeReleaseRanges(state.D_addrs, state);

        state.ra.safeRelease(state.S_regs);
        state.ra.safeRelease(state.D_regs);
        // Sum registers not freed here.

        state.S_layout.clear();
        state.D_layout.clear();
    };

    auto doSLoad = [&](const vector<RegisterBlock> &layout,
                           const vector<RegisterBlock> &layoutReflect,
                           const vector<GRFRange> &addrs,
                           const vector<GRFRange>(&addrSrcs)[2], int z0,
                           int s_load, int S_copy, bool checkRem) {
        bool unlockAP = false;
        Label skipLoad;
        checkRem &= (z0 > 0);

        if (checkRem) zeroMatrix(state.S_regs, strategy);
        if (checkRem) {
            unlockAP = !state.raVFlag.lock(state.flagAP);
            state.usePhysicalFlag(state.flagAP);
            cmp(1 | le | state.flagAP, state.Z, uint16_t(z0));
            jmpi(1 | state.flagAP, skipLoad);
        }
        loadMatrix(state.S_regs, layout, problem.S, strategy.S, addrs, strategy,
                state);

        auto addrsFixed = reflecting ? &addrSrcs[0] : &addrs;
        auto addrsStrided = reflecting ? &addrSrcs[1] : nullptr;
        auto layoutFixed = &layout;
        auto layoutStrided = &layoutReflect;

        if (sStrided) {
            std::swap(addrsFixed, addrsStrided);
            std::swap(layoutFixed, layoutStrided);
        }

        if (addrsStrided)
            incAddr(*addrsStrided,
                    (s_load == 1) ? state.inputs.lds : state.lds_sl,
                    *layoutStrided, problem.S, strategy.S, strategy, state);
        if (addrsFixed)
            incAddr(*addrsFixed, uint16_t(s_load * Ts), *layoutFixed, problem.S,
                    strategy.S, strategy, state);
        if (checkRem) {
            if (unlockAP) state.raVFlag.unlock(state.flagAP);
            mark(skipLoad);
        }
    };

    auto doDStore = [&](const vector<RegisterBlock> &layout,
                            const vector<GRFRange> &addrs, int d_load,
                            int D_copy) {
        storeMatrix(state.D_regs, layout, problem.D, strategy.D, addrs,
                strategy, state);
        if (problem.sum)
            accumulateSum(!byColumn, Td, state.D_regs, layout, Tsum,
                    state.Ds_regs.back(), state.Ds_layout, strategy, state);
        if (strategy.xLoop) {
            if (d_load >= strategy.unrollX)
                incAddr(addrs, state.ldd_dl, layout, problem.D, strategy.D,
                        strategy, state);
            else
                incAddr(addrs, uint16_t(d_load * Td), layout, problem.D,
                        strategy.D, strategy, state);
        } else {
            auto D_tileX = byColumn ? problem.D.tileR : problem.D.tileC;
            auto D_tileY = byColumn ? problem.D.tileC : problem.D.tileR;
            auto effPS = (d_load < D_tileY) ? D_tileX : problem.D.packSize;
            incAddr(addrs, uint16_t(d_load * effPS * Td), layout, problem.D,
                    strategy.D, strategy, state);
        }
    };

    // Start generating code.

    // Reuse z for the loop counter.
    // If z unroll > 1, the loop counter will be offset by (unrollZ - 1) during the main loop,
    //  unless there's no z remainder.
    // For triangular-ended copies, offset by an additional unrollW [2x unrollX if fused] to push triangular handling to remainder loop.
    state.Z = mLoop ? state.inputs.m : state.inputs.n;

    auto unrollZ = strategy.unrollZ();
    auto offsetZ = (remainderZ || triRemOnly) ? (unrollZ - 1) : 0;

    if (offsetZ == 0)
        cmp(1 | le | state.flagAP, null.d(), state.Z, int16_t(0));
    else
        add(1 | le | state.flagAP, state.Z, state.Z, int16_t(-offsetZ));

    // Get flag register and loop counter for barrier check if needed.
    FlagRegister flagBarrier;
    Subregister bcount;
    if (strategy.barrierFreq > 0) {
        flagBarrier = state.raVFlag.alloc();

        // Can use main loop counter if barrierFreq and unrollZ both powers of 2.
        if (!is_zero_or_pow2(strategy.barrierFreq * unrollZ)) {
            bcount = state.ra.alloc_sub<uint32_t>();
            mov(1, bcount, uint16_t(strategy.barrierFreq));
        }
    }

    // Setup for main loop.
    if (!setup(strategy.s_load, strategy.d_load, state.effS, state.effS1,
                state.effD, false))
        return false;

    bool lateZLoopCheck = state.vflagStorage.isValid();
    if (lateZLoopCheck) {
        // Release flags for use by vflags. Note flagReflect is not released.
        state.raVFlag.unlock(state.flagAP);
        if (flagBarrier.isValid()) state.raVFlag.unlock(flagBarrier);
    }

    // Bail to remainder loop if no main loops.
    jmpi(1 | state.flagAP, lZLoopEnd);

    // Loop check code.
    auto zLoopCheck = [&](int unrollZ, bool enableBarriers) {
        // Use the all-purpose flag for z loop query.
        add(1 | gt | state.flagAP, state.Z, state.Z, int16_t(-unrollZ));

        // Check for barrier if requested.
        if (enableBarriers) {
            if (bcount.isInvalid())
                and_(1 | ze | flagBarrier, null.ud(), state.Z,
                        uint16_t(unrollZ * strategy.barrierFreq - unrollZ));
            else
                add(1 | ze | flagBarrier, bcount, bcount, int16_t(-1));
        }
    };

    // Lambdas used in zLoopBody (moved outside to w/a GCC bug)
    auto mulAlphaFixed = [&](int esize, RegData r) {
        mul(esize, r, r, problem.alpha_real.getRegAvoiding(hw, r));
    };

    auto mulAlpha = [&](int esize, RegData r) {
        mul(esize, r, r, cast(Ts.real(), problem.alpha_real));
    };

    auto signChange = [&](int esize, RegData r) {
        auto ne = elementsPerGRF<uint32_t>(hw);
        xor_<uint32_t>(esize, r, r,
                (ne < esize) ? state.signChange[0](0, ne, 1)
                             : state.signChange[0](1));
    };

    // z loop: returns true on success.
    int S_copy = 0, D_copy = 0;
    auto zLoopBody = [&](const vector<RegisterBlock> &S_layout,
                             const vector<RegisterBlock> &S_layoutReflected,
                             const vector<RegisterBlock> &D_layout,
                             const vector<GRFRange> &S_addrs,
                             const vector<GRFRange>(&S_addrSrcs)[2],
                             const vector<GRFRange> &D_addrs, int unrollZ,
                             int s_load, int d_load, bool enableBarriers,
                             bool enableTri, bool needSRem = false,
                             bool noLoop = false) {
        int us = s_load, ud = 0;
        int uZLoopCheck = noLoop ? -1 : lateZLoopCheck ? (unrollZ - 1) : 0;
        bool dMasked = hasMasking(D_layout);

        for (int u = 0; u < unrollZ; u++, us++, ud++) {
            // Maintain us (= u % s_load) and ud (= u % d_load) counters.
            bool loadS = false;
            if (us == s_load) {
                us = 0;
                loadS = true;
            }

            if (ud == d_load) ud = 0;
            bool storeD = ((ud + 1) == d_load);

            // Test loop counter on first iteration (lateZLoopCheck == false)
            if ((u == uZLoopCheck) && !lateZLoopCheck)
                zLoopCheck(unrollZ, enableBarriers);

            // Load S every s_load loops, and copy as necessary.
            if (loadS) {
                doSLoad(S_layout, S_layoutReflected, S_addrs, S_addrSrcs, u,
                        s_load, S_copy, needSRem);

                // Copy S registers to D registers, or perform in-place scaling/transposition.
                if (!share) {
                    int dOffR = 0, dOffC = 0;
                    (byColumn ? dOffC : dOffR) = ud;

                    if (!copyRegisters(Ts, Td, S_layout, D_layout, state.S_regs,
                                state.D_regs, dOffR, dOffC, problem.alpha_real,
                                problem.alpha_imag, problem.conjugate, strategy,
                                state))
                        return false;
                } else {
                    if (!problem.alpha_real.fixed())
                        map(hw, Ts.real(), state.S_regs, S_layout, strategy,
                                mulAlphaFixed);
                    else if ((problem.alpha_real != 1)
                            && (problem.alpha_real != -1))
                        map(hw, Ts.real(), state.S_regs, S_layout, strategy,
                                mulAlpha);
                    if (problem.conjugate || (problem.alpha_real == -1))
                        map<uint32_t>(hw, state.S_regs, S_layout, strategy,
                                signChange);
                }

                // Advance S copy counter.
                if (++S_copy == SD_copies) S_copy = 0;
            }

            // Test loop counter on last iteration (lateZLoopCheck == true) if D unmasked.
            if ((u == uZLoopCheck) && lateZLoopCheck && !dMasked)
                zLoopCheck(unrollZ, enableBarriers);

            // Store D every d_load loops.
            if (storeD) {
                doDStore(D_layout, D_addrs, d_load, D_copy);
                if (++D_copy == SD_copies) D_copy = 0;
            }

            // Test loop counter at very end (lateZLoopCheck == true) if D masked.
            if ((u == uZLoopCheck) && lateZLoopCheck && dMasked)
                zLoopCheck(unrollZ, enableBarriers);
        }

        // Forget about active vflags.
        state.wipeActiveVFlags();

        return true;
    };

    syncall();

    mark(lZLoopBegin);
    {
        if (!zLoopBody(state.S_layout, S_layoutReflected, state.D_layout,
                    state.S_addrs, state.S_addrSrcs, state.D_addrs, unrollZ,
                    strategy.s_load, strategy.d_load, strategy.barrierFreq > 0,
                    !triRemOnly))
            return false;

        if (strategy.barrierFreq == 0)
            jmpi(1 | state.flagAP, lZLoopBegin);
        else {
            jmpi(1 | ~state.flagAP, lZLoopEnd);
            jmpi(1 | ~flagBarrier, lZLoopBegin);

            auto temp = state.ra.alloc();
            if (!bcount.isInvalid())
                mov(1, bcount, uint16_t(strategy.barrierFreq));

            GRF r0_info;
            bool freeR0Info = false;

            if (state.r0_info.isARF()) {
                r0_info = state.ra.alloc();
                mov<uint32_t>(8, r0_info, state.r0_info);
                freeR0Info = true;
            } else
                r0_info = GRF {state.r0_info.getBase()};

            barrier(temp, r0_info);
            state.ra.safeRelease(temp);
            if (freeR0Info) state.ra.safeRelease(r0_info);

            jmpi(1, lZLoopBegin);
        }
    }
    mark(lZLoopEnd);

    state.raVFlag.safeRelease(flagBarrier);
    state.ra.safeRelease(bcount);

    // z remainder loop.
    if (offsetZ) {
        // Undo offseting on the z loop counter and check for zero remainder loops.
        add(1 | le | state.flagAP, state.Z, state.Z, uint16_t(offsetZ));

        // Get the current S, D addresses.
        Subregister S_addr0, S1_addr0, D_addr0;
        int S_shift, D_shift;
        S_addr0 = getOriginAddr(
                state.S_layout, state.S_addrs, problem.S, strategy.S, &S_shift);

        D_addr0 = getOriginAddr(
                state.D_layout, state.D_addrs, problem.D, strategy.D, &D_shift);

        auto unshiftAddr0 = [&]() {
            if (S_shift) shl(1, S_addr0, S_addr0, S_shift);
            if (D_shift) shl(1, D_addr0, D_addr0, D_shift);
        };

        // Prepare for potential new layout.
        vector<RegisterBlock> S_layout1, S_layout1Reflect, D_layout1;
        vector<GRFRange> S_addrs1, S_addrSrcs1[2], D_addrs1;

        // First, try handling the whole remainder, all at once.
        bool wholeRem = false, fragmented = false;
        auto newSLoad = strategy.s_load, newDLoad = strategy.d_load;

        if (S_addr0.isValid() && D_addr0.isValid()) {
            auto saveState = state;
            auto saveMasks = masks;
            (strategy.xLoop ? state.remainderX : state.remainderY) = state.Z;
            pushStream();
            try {
                cleanup();
                state.ra.claim(S_addr0);
                state.ra.claim(D_addr0);
                unshiftAddr0();

                wholeRem = setup(strategy.s_load, strategy.d_load, S_addr0,
                        S1_addr0, D_addr0, true);

                state.ra.release(S_addr0);
                state.ra.release(D_addr0);
            } catch (...) {}
            if (!wholeRem) {
                masks = saveMasks;
                state = saveState;
            }
            wholeRem ? appendCurrentStream() : discardStream();
        }

        // If that doesn't work, retry with minimal unroll.
        if (!wholeRem) {
            newSLoad = 1;
            newDLoad = crosspack;
            bool unshare = share && (newSLoad != newDLoad);

            // Fragment the S, D layouts, taking the first row/column of each.
            vector<int> indices;
            fragmented = (!unshare
                    && getSubblocks(Ts, S_layout1, indices, state.S_layout,
                            !mLoop, 0, newSLoad, problem.S.padded, problem.S,
                            strategy.S)
                    && getSubblocks(Ts, S_layout1Reflect, S_layoutReflected,
                            mLoop, 0, newSLoad, problem.S.padded, problem.S,
                            S_strategyReflected)
                    && getSubblocks(Td, D_layout1, D_addrs1, state.D_layout,
                            state.D_addrs, !mLoop, 0, newDLoad, false,
                            problem.D, strategy.D));

            if (fragmented) {
                // Select source address registers from the fragments.
                for (auto b : indices)
                    S_addrs1.push_back(state.S_addrs[b]);
                // Update sizes.
                (mLoop ? nms : nns) = newSLoad;
                (mLoop ? nmd : nnd) = newDLoad;
            } else {
                // Fragmentation failed. Start fresh.
                if (S_addr0.isInvalid() || D_addr0.isInvalid()) return false;

                cleanup();
                state.ra.claim(S_addr0);
                state.ra.claim(D_addr0);
                unshiftAddr0();

                if (!setup(newSLoad, newDLoad, S_addr0, S1_addr0, D_addr0,
                            false))
                    return false;

                state.ra.release(S_addr0);
                state.ra.release(D_addr0);
            }

            if (crosspack > 1) {
                lateZLoopCheck = true;
                copyCalcIncrements(
                        problem, strategy, state, newSLoad, newDLoad);
            }
        }

        // Emit z remainder loop.
        Label lZRemLoopBegin, lZRemLoopEnd;
        jmpi(1 | state.flagAP, lZRemLoopEnd);
        mark(lZRemLoopBegin);
        wholeRem ? zLoopBody(state.S_layout, S_layoutReflected, state.D_layout,
                state.S_addrs, state.S_addrSrcs, state.D_addrs, unrollZ,
                newSLoad, newDLoad, false, true, false, !triRemOnly)
                 : fragmented
                        ? zLoopBody(S_layout1, S_layout1Reflect, D_layout1,
                                S_addrs1, S_addrSrcs1, D_addrs1, crosspack,
                                newSLoad, newDLoad, false, true, crosspack > 1)
                        : zLoopBody(state.S_layout, S_layoutReflected,
                                state.D_layout, state.S_addrs, state.S_addrSrcs,
                                state.D_addrs, crosspack, newSLoad, newDLoad,
                                false, true, crosspack > 1);
        if (!wholeRem || triRemOnly) jmpi(1 | state.flagAP, lZRemLoopBegin);
        mark(lZRemLoopEnd);
    }

    // Finalize and store sums.
    if (problem.sum) {
        horizontalAdd(!byColumn, Tsum, state.Ds_regs.back(), state.Ds_layout);

        // Accumulate sums from main and remainder loops.
        for (int l = 1; l < int(state.Ds_regs.size()); l++) {
            map(hw, Tsum, state.Ds_regs[0], state.Ds_regs[l], strategy,
                    [&](int ne, GRF r1, GRF r2) { add(ne, r1, r1, r2); });
            state.ra.safeRelease(state.Ds_regs[l]);
        }
        state.Ds_regs.resize(1);

        MatrixAddressing Ds = problem.D;
        Ds.crosspack = 1;

        MatrixAddressingStrategy Ds_strategy;
        Ds_strategy.accessType = AccessType::Block;

        int sr = 1, sc = 1;
        (byColumn ? sr : sc) = problem.D.packSize;

        vector<RegisterBlock> Ds_layoutOut;
        bool ok = getRegLayout(Tsum, Ds_layoutOut, sr, sc, false, false, true,
                          true, ScatterSIMD::Default, 0, 0, Ds, Ds_strategy)
                && matchLayouts(Tsum, Ds_layoutOut, state.Ds_layout);
        if (!ok) return false;

        vector<GRFRange> Ds_addrs;
        allocAddrRegs(Ds_addrs, Ds_layoutOut, Ds, Ds_strategy, state);

        Subregister Ds_base;
        Ds_base = state.ra.alloc_sub(state.effD.getType());

        mulConstant(1, Ds_base.ud(), state.inputs.ldd, problem.D.packSize * Td);
        add(1, Ds_base.ud(), Ds_base.ud(), -problem.D.packSize * Tsum);
        eadd(1, Ds_base, Ds_base.ud(), state.effD, strategy, state);

        setupAddr(Tsum, Ds_addrs, Ds_base, Ds_layoutOut, Subregister(), Ds,
                Ds_strategy, strategy, state);
        storeMatrix(state.Ds_regs[0], Ds_layoutOut, Ds, Ds_strategy, Ds_addrs,
                strategy, state);

        state.ra.safeRelease(Ds_base);
        safeReleaseRanges(Ds_addrs, state);
        safeReleaseRanges(state.Ds_regs, state);
        state.Ds_layout.clear();
        state.ra.safeRelease(state.all1s);
    }

    // Done. Free address, data, and flag registers.
    cleanup();
    state.ra.safeRelease(state.signChange);
    if (lateZLoopCheck) state.raVFlag.lock(state.flagAP);
    state.raVFlag.safeRelease(state.flagReflect);
    state.raVFlag.safeRelease(state.flagSwizzle);

    return true; /* Success! */
}

// Register-to-register copy of a single block, ignoring register offsets in the block.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyRegisterBlock(Type Ts, Type Td,
        const RegisterBlock &blockSrc, const RegisterBlock &blockDst,
        const GRFRange &src, const GRFRange &dst, int dOffR, int dOffC,
        const CommonStrategy &strategy, CommonState &state) {
    std::vector<RegisterBlock> modSrc {1, blockSrc}, modDst {1, blockDst};
    modSrc[0].offsetBytes %= GRF::bytes(hw);
    modDst[0].offsetBytes %= GRF::bytes(hw);
    return copyRegisters(Ts, Td, modSrc, modDst, src, dst, dOffR, dOffC, false,
            strategy, state);
}

// Register-to-register copy, with no scaling.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyRegisters(Type Ts, Type Td,
        const vector<RegisterBlock> &layoutSrc,
        const vector<RegisterBlock> &layoutDst, const GRFMultirange &src,
        const GRFMultirange &dst, int dOffR, int dOffC, bool conjugate,
        const CommonStrategy &strategy, CommonState &state) {
    return copyRegisters(Ts, Td, layoutSrc, layoutDst, src, dst, dOffR, dOffC,
            Scalar<double>(1.), Scalar<double>(0.), conjugate, strategy, state);
}

// Register-to-register copy, with scaling.
template <ngen::HW hw>
bool gemm_kernel_generator_t<hw>::copyRegisters(Type Ts, Type Td,
        const vector<RegisterBlock> &layoutSrc,
        const vector<RegisterBlock> &layoutDst, const GRFMultirange &src,
        const GRFMultirange &dst, int dOffR, int dOffC,
        const Scalar<double> &alpha_real, const Scalar<double> &alpha_imag,
        bool conjugate, const CommonStrategy &strategy, CommonState &state) {
    int nphases = 1;

    bool preswizzle = false;
    GRFRange copyTemp;

    auto allocTemp = [&]() {
        if (preswizzle && copyTemp.isInvalid())
            copyTemp = state.ra.alloc_range(2);
    };

    for (int phase = 0; phase < nphases; phase++) {
        for (auto &sblock : layoutSrc) {
            auto RegisterBlock::*nx
                    = sblock.colMajor ? &RegisterBlock::nr : &RegisterBlock::nc;
            auto RegisterBlock::*ny
                    = sblock.colMajor ? &RegisterBlock::nc : &RegisterBlock::nr;

            for (int eoffY = 0; eoffY < sblock.*ny; eoffY++) {
                for (int eoffX = 0; eoffX < sblock.*nx;) {
                    auto eoffR = sblock.colMajor ? eoffX : eoffY;
                    auto eoffC = sblock.colMajor ? eoffY : eoffX;

                    int selems, delems;
                    const RegisterBlock *sblockPtr, *dblockPtr;

                    // Locate source and destination register.
                    auto sreg = findBlockReg(Ts, layoutSrc,
                            sblock.offsetR + eoffR, sblock.offsetC + eoffC, src,
                            selems, sblockPtr);
                    auto dreg = findBlockReg(Td, layoutDst,
                            sblock.offsetR + eoffR + dOffR,
                            sblock.offsetC + eoffC + dOffC, dst, delems,
                            dblockPtr);

                    auto scrosspack = sblock.crosspack;
                    auto dcrosspack = dblockPtr->crosspack;

                    if (sblock.colMajor != dblockPtr->colMajor)
                        stub(); // No in-register transposes.

                    // Find out how many consecutive elements we can copy.
                    auto nGRFs = (strategy.dualGRF ? 2 : 1);
                    auto nGRFs_d = (dreg.getOffset() >= dcrosspack)
                            ? 1
                            : nGRFs; // Don't cross destination GRF boundaries for efficiency.
                    auto selems_real = selems * Ts.components();
                    auto delems_real = delems * Td.components();
                    auto selems_limit
                            = div_up(nGRFs * elementsPerGRF(hw, Ts.real())
                                            - sreg.getOffset(),
                                    scrosspack);
                    auto delems_limit
                            = div_up(nGRFs_d * elementsPerGRF(hw, Td.real())
                                            - dreg.getOffset(),
                                    dcrosspack);
                    selems_real = std::min({selems_real, selems_limit});
                    delems_real = std::min({delems_real, delems_limit});
                    auto nelems_real = std::min(selems_real, delems_real);
                    nelems_real = rounddown_pow2(nelems_real);

                    if (Ts == Type::f32 && Td != Type::f32 && dcrosspack == 1)
                        nelems_real = std::min(nelems_real,
                                elementsPerGRF(hw,
                                        Ts)); // Special case: mixed mode packed downconversion limited to SIMD8.

                    // Finally, copy, with any necessary conjugation and scaling. If doing a raw copy, use another pipe.
                    switch (phase) {
                        case 0:
                            if (alpha_real == 1 || alpha_real == -1) {
                                if (Ts.real() == Td.real()) {
                                    movePipes(sreg, scrosspack == 1);
                                    movePipes(dreg, scrosspack == 1);
                                }
                                int telems = nelems_real * Ts.real()
                                        / sreg.getBytes();
                                if (alpha_real == -1) {
                                    auto wd = elementsPerGRF(
                                            hw, sreg.getType());
                                    auto base = state.signChange.sub(
                                            0, dreg.getType());
                                    xor_(telems, dreg(1), sreg(1),
                                            (wd >= telems) ? base(1)
                                                           : base(0, wd, 1));
                                } else
                                    emov(telems, dreg(dcrosspack),
                                            sreg(scrosspack), strategy);
                            } else {
                                auto realDst = dreg(dcrosspack);
                                auto effDst = realDst;
                                if (preswizzle && (Ts.isFP() || Td.isFP())) {
                                    allocTemp();
                                    if ((sreg.getOffset() != dreg.getOffset())
                                            || (scrosspack != dcrosspack))
                                        effDst = copyTemp[0].sub(
                                                sreg.getOffset(),
                                                sreg.getType())(scrosspack);
                                }

                                if (alpha_real.fixed())
                                    mul(nelems_real, effDst, sreg(scrosspack),
                                            cast(Ts.real(), alpha_real));
                                else
                                    mul(nelems_real, effDst, sreg(scrosspack),
                                            alpha_real.getRegAvoiding(
                                                    hw, sreg));

                                if (effDst != realDst) {
                                    moveToIntPipe(nelems_real, realDst);
                                    moveToIntPipe(nelems_real, effDst);
                                    int nelems_real_int = nelems_real * Td
                                            / getBytes(effDst.getType());
                                    emov(nelems_real_int, realDst, effDst,
                                            strategy);
                                }
                            }
                            break;
                    }

                    eoffX += nelems_real / Ts.components();
                }
            }
        }
    }

    state.ra.safeRelease(copyTemp);
    return true; // Success
}

// Get driver information from this strategy.
CommonDriverInfo CopyStrategy::driverInfo(const CopyProblem &problem) const {
    CommonDriverInfo info;
    bool isA = (problem.D.layout == MatrixLayout::Pc);

    info.subgroupSize = subgroupSize;
    info.fusedEUs = problem.fused;
    info.unroll[0] = isA ? unrollX : unrollY;
    info.unroll[1] = isA ? unrollY : unrollX;
    info.kRemainderHandling = (remHandlingY != RemainderHandling::Ignore);
    info.loopOrder[0] = (isA ^ xLoop) ? LoopM : LoopN;
    info.wg[0] = 16;
    info.fixedWG = false;
    info.kBlocking = zBlocking;

    return info;
}

// Perform a sanity check on the strategy, correcting settings as necessary.
void CopyStrategy::sanityCheck(HW hw, const CopyProblem &problem) {
    bool cm = isColMajor(problem.D.layout);

    s_load = std::max(s_load, 1);
    d_load = std::max(d_load, 1);
    s_load_masked = std::max(s_load_masked, 1);
    d_load_masked = std::max(d_load_masked, 1);
    unrollX = std::max(unrollX, 1);
    unrollY = std::max(unrollY, 1);

    // Ensure d_load is a multiple of s_load, and unrollZ a multiple of both.
    // For x loop kernels, ensure s_load is a multiple of the packing size.
    // For y loop kernels, ensure all d_loads are multiples of y tile size if any.
    if (xLoop) {
        s_load = align_up(s_load, problem.D.packSize);
        s_load_masked = align_up(s_load_masked, problem.D.packSize);
    } else {
        auto D_tileY = cm ? problem.D.tileC : problem.D.tileR;
        if (D_tileY > 0) d_load_masked = align_up(d_load_masked, D_tileY);
    }
    d_load = align_up(d_load, s_load);
    d_load_masked = align_up(d_load_masked, s_load_masked);
    d_load = align_up(d_load, d_load_masked);

    if (xLoop)
        unrollX = align_up(unrollX, d_load);
    else
        unrollY = align_up(unrollY, d_load);

    if (unrollY == 1 && remHandlingY == RemainderHandling::Split)
        remHandlingY = RemainderHandling::General;

    spf &= !problem.trsm; // TRSM copies use SIMT control flow.

    CommonStrategy::sanityCheck(hw, problem);
}

/**********************************************************************/
/*                      Common Kernel Functions                       */
/**********************************************************************/

// Generate the kernel prologue.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::prologue(const CommonStrategy &strategy) {
    uint16_t cr0Enable;

    cr0Enable = 0x1000; // IEEE float->int rounding.
    if (strategy.ieeeDenormals) cr0Enable |= 0x4C0; // Enable hf|f|df denormals.
    if (strategy.spf) cr0Enable |= 0x4; // Enable single program flow.

    or_(1, cr0, cr0, cr0Enable);

    InstructionModifier imod = 1;
    if (hw < HW::Xe_LP) imod |= Switch;

    if (interface.getSIMD() < 16) mov(imod, sr0[2], uint16_t(0xFFFF));
}

// Generate the kernel epilogue.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::epilogue(
        const CommonStrategy &strategy, const CommonState &state) {
    auto r0_info = state.r0_info;

    if (r0_info.getBase() < 112) {
        mov<uint32_t>(8, r127, r0_info);
        r0_info = r127;
    }

    if (strategy.finalFence) {
        memfence(r124, r0_info);
        mov<uint32_t>(8, null, r124);
    }

    threadend(r0_info);
}

// Pad the end of the kernel to accommodate instruction prefetching.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::padding() {
    for (int q = 0; q < 8; q++)
        nop();
}

// Common state initialization code.
template <ngen::HW hw>
void gemm_kernel_generator_t<hw>::initState(const CommonProblem &problem,
        const CommonStrategy &strategy, CommonState &state) {
    if (problem.wgSupport) {
        interface.requireLocalID(3);
        interface.requireLocalSize();
    }

    if (problem.nonuniformWGs) interface.requireNonuniformWGs();

    if (strategy.wgInSS) interface.requireBarrier();

    interface.requireSIMD(strategy.subgroupSize);

    if (!strategy.sipR0WA) interface.requireNoPreemption();

    if (problem.gtpinSupport) interface.requireScratch(128);

    for (int i = 0; i < FlagRegister::subcount(hw); i++)
        state.activeVFlags[i].clear();
}

void CommonStrategy::sanityCheck(HW hw, const CommonProblem &problem) {
    sipR0WA &= (hw == HW::Gen9);
    if (sipR0WA && (moveR0 == MoveR0::None)) moveR0 = MoveR0::GRF;
    readSuppressionWA &= problem.fused;
}

template <ngen::HW hw>
constexpr typename gemm_kernel_generator_t<hw>::status_stream::Endl
        gemm_kernel_generator_t<hw>::status_stream::endl;

template class gemm_kernel_generator_t<HW::Gen9>;
template class gemm_kernel_generator_t<HW::Xe_LP>;

} // namespace jit
} // namespace gpu
} // namespace impl
} // namespace dnnl
