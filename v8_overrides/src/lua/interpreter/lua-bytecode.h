// Copyright 2019 Streamy. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LUA_LUA_BYTECODE_H_
#define V8_LUA_LUA_BYTECODE_H_

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "src/globals.h"
#include "src/lua/lua-bytecode-operands.h"

// This interface and it's implementation are independent of the
// libv8_base library as they are used by the interpreter and the
// standalone mkpeephole table generator program.

namespace v8 {
namespace internal {
namespace lua {

// The list of bytecodes which are interpreted by the interpreter.
// Format is V(<bytecode>, <accumulator_use>, <operands>).
#define BYTECODE_LIST(V)                                                       \
  /* Extended width operands */                                                \
  V(Wide, AccumulatorUse::kNone)                                               \
  V(ExtraWide, AccumulatorUse::kNone)                                          \
                                                                               \
  /* Loading the accumulator */                                                \
  V(LdaZero, AccumulatorUse::kWrite)                                           \
  V(LdaSmi, AccumulatorUse::kWrite, OperandType::kImm)                         \
  V(LdaUndefined, AccumulatorUse::kWrite)                                      \
  V(LdaNull, AccumulatorUse::kWrite)                                           \
  V(LdaTheHole, AccumulatorUse::kWrite)                                        \
  V(LdaTrue, AccumulatorUse::kWrite)                                           \
  V(LdaFalse, AccumulatorUse::kWrite)                                          \
  V(LdaConstant, AccumulatorUse::kWrite, OperandType::kIdx)                    \
                                                                               \
  /* Globals */                                                                \
  V(LdaGlobal, AccumulatorUse::kWrite, OperandType::kIdx, OperandType::kIdx)   \
  V(LdaGlobalInsideTypeof, AccumulatorUse::kWrite, OperandType::kIdx,          \
    OperandType::kIdx)                                                         \
  V(StaGlobal, AccumulatorUse::kRead, OperandType::kIdx, OperandType::kIdx)    \
                                                                               \
  /* Context operations */                                                     \
  V(PushContext, AccumulatorUse::kRead, OperandType::kRegOut)                  \
  V(PopContext, AccumulatorUse::kNone, OperandType::kReg)                      \
  V(LdaContextSlot, AccumulatorUse::kWrite, OperandType::kReg,                 \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(LdaImmutableContextSlot, AccumulatorUse::kWrite, OperandType::kReg,        \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(LdaCurrentContextSlot, AccumulatorUse::kWrite, OperandType::kIdx)          \
  V(LdaImmutableCurrentContextSlot, AccumulatorUse::kWrite, OperandType::kIdx) \
  V(StaContextSlot, AccumulatorUse::kRead, OperandType::kReg,                  \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(StaCurrentContextSlot, AccumulatorUse::kRead, OperandType::kIdx)           \
                                                                               \
  /* Load-Store lookup slots */                                                \
  V(LdaLookupSlot, AccumulatorUse::kWrite, OperandType::kIdx)                  \
  V(LdaLookupContextSlot, AccumulatorUse::kWrite, OperandType::kIdx,           \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(LdaLookupGlobalSlot, AccumulatorUse::kWrite, OperandType::kIdx,            \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(LdaLookupSlotInsideTypeof, AccumulatorUse::kWrite, OperandType::kIdx)      \
  V(LdaLookupContextSlotInsideTypeof, AccumulatorUse::kWrite,                  \
    OperandType::kIdx, OperandType::kIdx, OperandType::kUImm)                  \
  V(LdaLookupGlobalSlotInsideTypeof, AccumulatorUse::kWrite,                   \
    OperandType::kIdx, OperandType::kIdx, OperandType::kUImm)                  \
  V(StaLookupSlot, AccumulatorUse::kReadWrite, OperandType::kIdx,              \
    OperandType::kFlag8)                                                       \
                                                                               \
  /* Register-accumulator transfers */                                         \
  V(Ldar, AccumulatorUse::kWrite, OperandType::kReg)                           \
  V(Star, AccumulatorUse::kRead, OperandType::kRegOut)                         \
                                                                               \
  /* Register-register transfers */                                            \
  V(Mov, AccumulatorUse::kNone, OperandType::kReg, OperandType::kRegOut)       \
                                                                               \
  /* Property loads (LoadIC) operations */                                     \
  V(LdaNamedProperty, AccumulatorUse::kWrite, OperandType::kReg,               \
    OperandType::kIdx, OperandType::kIdx)                                      \
  V(LdaKeyedProperty, AccumulatorUse::kReadWrite, OperandType::kReg,           \
    OperandType::kIdx)                                                         \
                                                                               \
  /* Operations on module variables */                                         \
  V(LdaModuleVariable, AccumulatorUse::kWrite, OperandType::kImm,              \
    OperandType::kUImm)                                                        \
  V(StaModuleVariable, AccumulatorUse::kRead, OperandType::kImm,               \
    OperandType::kUImm)                                                        \
                                                                               \
  /* Propery stores (StoreIC) operations */                                    \
  V(StaNamedProperty, AccumulatorUse::kReadWrite, OperandType::kReg,           \
    OperandType::kIdx, OperandType::kIdx)                                      \
  V(StaNamedOwnProperty, AccumulatorUse::kReadWrite, OperandType::kReg,        \
    OperandType::kIdx, OperandType::kIdx)                                      \
  V(StaKeyedProperty, AccumulatorUse::kReadWrite, OperandType::kReg,           \
    OperandType::kReg, OperandType::kIdx)                                      \
  V(StaInArrayLiteral, AccumulatorUse::kReadWrite, OperandType::kReg,          \
    OperandType::kReg, OperandType::kIdx)                                      \
  V(StaDataPropertyInLiteral, AccumulatorUse::kRead, OperandType::kReg,        \
    OperandType::kReg, OperandType::kFlag8, OperandType::kIdx)                 \
  V(CollectTypeProfile, AccumulatorUse::kRead, OperandType::kImm)              \
                                                                               \
  /* Binary Operators */                                                       \
  V(Add, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(Sub, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(Mul, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(Div, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(Mod, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(Exp, AccumulatorUse::kReadWrite, OperandType::kReg, OperandType::kIdx)     \
  V(BitwiseOr, AccumulatorUse::kReadWrite, OperandType::kReg,                  \
    OperandType::kIdx)                                                         \
  V(BitwiseXor, AccumulatorUse::kReadWrite, OperandType::kReg,                 \
    OperandType::kIdx)                                                         \
  V(BitwiseAnd, AccumulatorUse::kReadWrite, OperandType::kReg,                 \
    OperandType::kIdx)                                                         \
  V(ShiftLeft, AccumulatorUse::kReadWrite, OperandType::kReg,                  \
    OperandType::kIdx)                                                         \
  V(ShiftRight, AccumulatorUse::kReadWrite, OperandType::kReg,                 \
    OperandType::kIdx)                                                         \
  V(ShiftRightLogical, AccumulatorUse::kReadWrite, OperandType::kReg,          \
    OperandType::kIdx)                                                         \
                                                                               \
  /* Binary operators with immediate operands */                               \
  V(AddSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(SubSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(MulSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(DivSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(ModSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(ExpSmi, AccumulatorUse::kReadWrite, OperandType::kImm, OperandType::kIdx)  \
  V(BitwiseOrSmi, AccumulatorUse::kReadWrite, OperandType::kImm,               \
    OperandType::kIdx)                                                         \
  V(BitwiseXorSmi, AccumulatorUse::kReadWrite, OperandType::kImm,              \
    OperandType::kIdx)                                                         \
  V(BitwiseAndSmi, AccumulatorUse::kReadWrite, OperandType::kImm,              \
    OperandType::kIdx)                                                         \
  V(ShiftLeftSmi, AccumulatorUse::kReadWrite, OperandType::kImm,               \
    OperandType::kIdx)                                                         \
  V(ShiftRightSmi, AccumulatorUse::kReadWrite, OperandType::kImm,              \
    OperandType::kIdx)                                                         \
  V(ShiftRightLogicalSmi, AccumulatorUse::kReadWrite, OperandType::kImm,       \
    OperandType::kIdx)                                                         \
                                                                               \
  /* Unary Operators */                                                        \
  V(Inc, AccumulatorUse::kReadWrite, OperandType::kIdx)                        \
  V(Dec, AccumulatorUse::kReadWrite, OperandType::kIdx)                        \
  V(Negate, AccumulatorUse::kReadWrite, OperandType::kIdx)                     \
  V(BitwiseNot, AccumulatorUse::kReadWrite, OperandType::kIdx)                 \
  V(ToBooleanLogicalNot, AccumulatorUse::kReadWrite)                           \
  V(LogicalNot, AccumulatorUse::kReadWrite)                                    \
  V(TypeOf, AccumulatorUse::kReadWrite)                                        \
  V(DeletePropertyStrict, AccumulatorUse::kReadWrite, OperandType::kReg)       \
  V(DeletePropertySloppy, AccumulatorUse::kReadWrite, OperandType::kReg)       \
                                                                               \
  /* GetSuperConstructor operator */                                           \
  V(GetSuperConstructor, AccumulatorUse::kRead, OperandType::kRegOut)          \
                                                                               \
  /* Call operations */                                                        \
  V(CallAnyReceiver, AccumulatorUse::kWrite, OperandType::kReg,                \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
  V(CallProperty, AccumulatorUse::kWrite, OperandType::kReg,                   \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
  V(CallProperty0, AccumulatorUse::kWrite, OperandType::kReg,                  \
    OperandType::kReg, OperandType::kIdx)                                      \
  V(CallProperty1, AccumulatorUse::kWrite, OperandType::kReg,                  \
    OperandType::kReg, OperandType::kReg, OperandType::kIdx)                   \
  V(CallProperty2, AccumulatorUse::kWrite, OperandType::kReg,                  \
    OperandType::kReg, OperandType::kReg, OperandType::kReg,                   \
    OperandType::kIdx)                                                         \
  V(CallUndefinedReceiver, AccumulatorUse::kWrite, OperandType::kReg,          \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
  V(CallUndefinedReceiver0, AccumulatorUse::kWrite, OperandType::kReg,         \
    OperandType::kIdx)                                                         \
  V(CallUndefinedReceiver1, AccumulatorUse::kWrite, OperandType::kReg,         \
    OperandType::kReg, OperandType::kIdx)                                      \
  V(CallUndefinedReceiver2, AccumulatorUse::kWrite, OperandType::kReg,         \
    OperandType::kReg, OperandType::kReg, OperandType::kIdx)                   \
  V(CallWithSpread, AccumulatorUse::kWrite, OperandType::kReg,                 \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
  V(CallRuntime, AccumulatorUse::kWrite, OperandType::kRuntimeId,              \
    OperandType::kRegList, OperandType::kRegCount)                             \
  V(CallRuntimeForPair, AccumulatorUse::kNone, OperandType::kRuntimeId,        \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kRegOutPair)   \
  V(CallJSRuntime, AccumulatorUse::kWrite, OperandType::kNativeContextIndex,   \
    OperandType::kRegList, OperandType::kRegCount)                             \
                                                                               \
  /* Intrinsics */                                                             \
  V(InvokeIntrinsic, AccumulatorUse::kWrite, OperandType::kIntrinsicId,        \
    OperandType::kRegList, OperandType::kRegCount)                             \
                                                                               \
  /* Construct operators */                                                    \
  V(Construct, AccumulatorUse::kReadWrite, OperandType::kReg,                  \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
  V(ConstructWithSpread, AccumulatorUse::kReadWrite, OperandType::kReg,        \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kIdx)          \
                                                                               \
  /* Test Operators */                                                         \
  V(TestEqual, AccumulatorUse::kReadWrite, OperandType::kReg,                  \
    OperandType::kIdx)                                                         \
  V(TestEqualStrict, AccumulatorUse::kReadWrite, OperandType::kReg,            \
    OperandType::kIdx)                                                         \
  V(TestLessThan, AccumulatorUse::kReadWrite, OperandType::kReg,               \
    OperandType::kIdx)                                                         \
  V(TestGreaterThan, AccumulatorUse::kReadWrite, OperandType::kReg,            \
    OperandType::kIdx)                                                         \
  V(TestLessThanOrEqual, AccumulatorUse::kReadWrite, OperandType::kReg,        \
    OperandType::kIdx)                                                         \
  V(TestGreaterThanOrEqual, AccumulatorUse::kReadWrite, OperandType::kReg,     \
    OperandType::kIdx)                                                         \
  V(TestReferenceEqual, AccumulatorUse::kReadWrite, OperandType::kReg)         \
  V(TestInstanceOf, AccumulatorUse::kReadWrite, OperandType::kReg,             \
    OperandType::kIdx)                                                         \
  V(TestIn, AccumulatorUse::kReadWrite, OperandType::kReg)                     \
  V(TestUndetectable, AccumulatorUse::kReadWrite)                              \
  V(TestNull, AccumulatorUse::kReadWrite)                                      \
  V(TestUndefined, AccumulatorUse::kReadWrite)                                 \
  V(TestTypeOf, AccumulatorUse::kReadWrite, OperandType::kFlag8)               \
                                                                               \
  /* Cast operators */                                                         \
  V(ToName, AccumulatorUse::kRead, OperandType::kRegOut)                       \
  V(ToNumber, AccumulatorUse::kReadWrite, OperandType::kIdx)                   \
  V(ToNumeric, AccumulatorUse::kReadWrite, OperandType::kIdx)                  \
  V(ToObject, AccumulatorUse::kRead, OperandType::kRegOut)                     \
  V(ToString, AccumulatorUse::kReadWrite)                                      \
                                                                               \
  /* Literals */                                                               \
  V(CreateRegExpLiteral, AccumulatorUse::kWrite, OperandType::kIdx,            \
    OperandType::kIdx, OperandType::kFlag8)                                    \
  V(CreateArrayLiteral, AccumulatorUse::kWrite, OperandType::kIdx,             \
    OperandType::kIdx, OperandType::kFlag8)                                    \
  V(CreateEmptyArrayLiteral, AccumulatorUse::kWrite, OperandType::kIdx)        \
  V(CreateObjectLiteral, AccumulatorUse::kNone, OperandType::kIdx,             \
    OperandType::kIdx, OperandType::kFlag8, OperandType::kRegOut)              \
  V(CreateEmptyObjectLiteral, AccumulatorUse::kWrite)                          \
                                                                               \
  /* Tagged templates */                                                       \
  V(GetTemplateObject, AccumulatorUse::kWrite, OperandType::kIdx,              \
    OperandType::kIdx)                                                         \
                                                                               \
  /* Closure allocation */                                                     \
  V(CreateClosure, AccumulatorUse::kWrite, OperandType::kIdx,                  \
    OperandType::kIdx, OperandType::kFlag8)                                    \
                                                                               \
  /* Context allocation */                                                     \
  V(CreateBlockContext, AccumulatorUse::kReadWrite, OperandType::kIdx)         \
  V(CreateCatchContext, AccumulatorUse::kReadWrite, OperandType::kReg,         \
    OperandType::kIdx, OperandType::kIdx)                                      \
  V(CreateFunctionContext, AccumulatorUse::kWrite, OperandType::kUImm)         \
  V(CreateEvalContext, AccumulatorUse::kWrite, OperandType::kUImm)             \
  V(CreateWithContext, AccumulatorUse::kReadWrite, OperandType::kReg,          \
    OperandType::kIdx)                                                         \
                                                                               \
  /* Arguments allocation */                                                   \
  V(CreateMappedArguments, AccumulatorUse::kWrite)                             \
  V(CreateUnmappedArguments, AccumulatorUse::kWrite)                           \
  V(CreateRestParameter, AccumulatorUse::kWrite)                               \
                                                                               \
  /* Control Flow -- carefully ordered for efficient checks */                 \
  /* - [Unconditional jumps] */                                                \
  V(JumpLoop, AccumulatorUse::kNone, OperandType::kUImm, OperandType::kImm)    \
  /* - [Forward jumps] */                                                      \
  V(Jump, AccumulatorUse::kNone, OperandType::kUImm)                           \
  /* - [Start constant jumps] */                                               \
  V(JumpConstant, AccumulatorUse::kNone, OperandType::kIdx)                    \
  /* - [Conditional jumps] */                                                  \
  /* - [Conditional constant jumps] */                                         \
  V(JumpIfNullConstant, AccumulatorUse::kRead, OperandType::kIdx)              \
  V(JumpIfNotNullConstant, AccumulatorUse::kRead, OperandType::kIdx)           \
  V(JumpIfUndefinedConstant, AccumulatorUse::kRead, OperandType::kIdx)         \
  V(JumpIfNotUndefinedConstant, AccumulatorUse::kRead, OperandType::kIdx)      \
  V(JumpIfTrueConstant, AccumulatorUse::kRead, OperandType::kIdx)              \
  V(JumpIfFalseConstant, AccumulatorUse::kRead, OperandType::kIdx)             \
  V(JumpIfJSReceiverConstant, AccumulatorUse::kRead, OperandType::kIdx)        \
  /* - [Start ToBoolean jumps] */                                              \
  V(JumpIfToBooleanTrueConstant, AccumulatorUse::kRead, OperandType::kIdx)     \
  V(JumpIfToBooleanFalseConstant, AccumulatorUse::kRead, OperandType::kIdx)    \
  /* - [End constant jumps] */                                                 \
  /* - [Conditional immediate jumps] */                                        \
  V(JumpIfToBooleanTrue, AccumulatorUse::kRead, OperandType::kUImm)            \
  V(JumpIfToBooleanFalse, AccumulatorUse::kRead, OperandType::kUImm)           \
  /* - [End ToBoolean jumps] */                                                \
  V(JumpIfTrue, AccumulatorUse::kRead, OperandType::kUImm)                     \
  V(JumpIfFalse, AccumulatorUse::kRead, OperandType::kUImm)                    \
  V(JumpIfNull, AccumulatorUse::kRead, OperandType::kUImm)                     \
  V(JumpIfNotNull, AccumulatorUse::kRead, OperandType::kUImm)                  \
  V(JumpIfUndefined, AccumulatorUse::kRead, OperandType::kUImm)                \
  V(JumpIfNotUndefined, AccumulatorUse::kRead, OperandType::kUImm)             \
  V(JumpIfJSReceiver, AccumulatorUse::kRead, OperandType::kUImm)               \
                                                                               \
  /* Smi-table lookup for switch statements */                                 \
  V(SwitchOnSmiNoFeedback, AccumulatorUse::kRead, OperandType::kIdx,           \
    OperandType::kUImm, OperandType::kImm)                                     \
                                                                               \
  /* Complex flow control For..in */                                           \
  V(ForInEnumerate, AccumulatorUse::kWrite, OperandType::kReg)                 \
  V(ForInPrepare, AccumulatorUse::kRead, OperandType::kRegOutTriple,           \
    OperandType::kIdx)                                                         \
  V(ForInContinue, AccumulatorUse::kWrite, OperandType::kReg,                  \
    OperandType::kReg)                                                         \
  V(ForInNext, AccumulatorUse::kWrite, OperandType::kReg, OperandType::kReg,   \
    OperandType::kRegPair, OperandType::kIdx)                                  \
  V(ForInStep, AccumulatorUse::kWrite, OperandType::kReg)                      \
                                                                               \
  /* Perform a stack guard check */                                            \
  V(StackCheck, AccumulatorUse::kNone)                                         \
                                                                               \
  /* Update the pending message */                                             \
  V(SetPendingMessage, AccumulatorUse::kReadWrite)                             \
                                                                               \
  /* Non-local flow control */                                                 \
  V(Throw, AccumulatorUse::kRead)                                              \
  V(ReThrow, AccumulatorUse::kRead)                                            \
  V(Return, AccumulatorUse::kRead)                                             \
  V(ThrowReferenceErrorIfHole, AccumulatorUse::kRead, OperandType::kIdx)       \
  V(ThrowSuperNotCalledIfHole, AccumulatorUse::kRead)                          \
  V(ThrowSuperAlreadyCalledIfNotHole, AccumulatorUse::kRead)                   \
                                                                               \
  /* Generators */                                                             \
  V(SwitchOnGeneratorState, AccumulatorUse::kNone, OperandType::kReg,          \
    OperandType::kIdx, OperandType::kUImm)                                     \
  V(SuspendGenerator, AccumulatorUse::kRead, OperandType::kReg,                \
    OperandType::kRegList, OperandType::kRegCount, OperandType::kUImm)         \
  V(ResumeGenerator, AccumulatorUse::kWrite, OperandType::kReg,                \
    OperandType::kRegOutList, OperandType::kRegCount)                          \
                                                                               \
  /* Debugger */                                                               \
  V(Debugger, AccumulatorUse::kNone)                                           \
                                                                               \
  /* Debug Breakpoints - one for each possible size of unscaled bytecodes */   \
  /* and one for each operand widening prefix bytecode                    */   \
  V(DebugBreak0, AccumulatorUse::kReadWrite)                                   \
  V(DebugBreak1, AccumulatorUse::kReadWrite, OperandType::kReg)                \
  V(DebugBreak2, AccumulatorUse::kReadWrite, OperandType::kReg,                \
    OperandType::kReg)                                                         \
  V(DebugBreak3, AccumulatorUse::kReadWrite, OperandType::kReg,                \
    OperandType::kReg, OperandType::kReg)                                      \
  V(DebugBreak4, AccumulatorUse::kReadWrite, OperandType::kReg,                \
    OperandType::kReg, OperandType::kReg, OperandType::kReg)                   \
  V(DebugBreak5, AccumulatorUse::kReadWrite, OperandType::kRuntimeId,          \
    OperandType::kReg, OperandType::kReg)                                      \
  V(DebugBreak6, AccumulatorUse::kReadWrite, OperandType::kRuntimeId,          \
    OperandType::kReg, OperandType::kReg, OperandType::kReg)                   \
  V(DebugBreakWide, AccumulatorUse::kReadWrite)                                \
  V(DebugBreakExtraWide, AccumulatorUse::kReadWrite)                           \
                                                                               \
  /* Block Coverage */                                                         \
  V(IncBlockCounter, AccumulatorUse::kNone, OperandType::kIdx)                 \
                                                                               \
  /* Execution Abort (internal error) */                                       \
  V(Abort, AccumulatorUse::kNone, OperandType::kIdx)                           \
                                                                               \
  /* Illegal bytecode  */                                                      \
  V(Illegal, AccumulatorUse::kNone)


}  // namespace lua
}  // namespace internal
}  // namespace v8

#endif  // V8_LUA_LUA_BYTECODE_H_