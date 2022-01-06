//
// Copyright 2019 ZetaSQL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// resolved_ast_deep_copy_visitor.h GENERATED FROM resolved_ast_deep_copy_visitor.h.template

#ifndef ZETASQL_RESOLVED_AST_RESOLVED_AST_DEEP_COPY_VISITOR_H_
#define ZETASQL_RESOLVED_AST_RESOLVED_AST_DEEP_COPY_VISITOR_H_

#include <algorithm>
#include <memory>
#include <stack>
#include <utility>
#include <vector>

#include "zetasql/base/logging.h"
#include "zetasql/resolved_ast/resolved_ast.h"
#include "zetasql/resolved_ast/resolved_ast_visitor.h"
#include "zetasql/resolved_ast/resolved_node.h"
#include "zetasql/base/ret_check.h"
#include "zetasql/base/status.h"
#include "zetasql/base/statusor.h"

namespace zetasql {

// This is the base class for deep-copy rewriter classes.
//
// It provides the utility functions to handle the data flow and the
// implementations for copying individual node types. This can be subclassed to
// create a copy of the AST with modifications.
//
// This class uses a stack which always contains exactly one or zero elements.
// The stack is used as a holding place for a recursive-like bottom up copying
// of the AST.
//
// The stack is used for making the recursive copying work:
// 1. Each call to VisitX pushes its returned node on the stack.
// 2. The caller of VisitX (which called node->Accept()) pops the
//    returned node from the stack.
// 3. The entire copied tree is available using ConsumeRootNode() in the end.
//
// To more concretely show how the stack is used, consider this FunctionCall.
//
// +-FunctionCall(ZetaSQL:$add(INT64, INT64) -> INT64)
//   +-ColumnRef(type=INT64, column=KeyValue.Key#1)
//   +-Literal(type=INT64, value=1)
//
// In order to get a deep copy of the FunctionCall, we must get a deep copy
// of the two child nodes, since they are owned by the parent node.
// To accomplish this, we call Accept on
// each of them, triggering CopyVisitResolvedX. It is guaranteed that
// CopyVisitResolvedX must push exactly one node to the stack, so we can
// consume the deep copied node from the top of the stack. Then, we can create
// our deep copied function call by using the two consumed stack values and
// push it to the stack for it's consumer.
//
// This allows us to perform a bottom-up deep copy.
//
// At the end of each CopyVisitX method, there should be exactly one element
// on the stack -- the copied (or possibly copied/modified) version of X. If
// there was more than one element on the stack, it would imply that a copied
// value was not consumed. If there were zero elements on the stack, a consumer
// would not have any node to consume. Once the final CopyVisitX is called, it
// will remain on the stack to be consumed by ConsumeRootNode, giving a copy of
// the entire AST.
//
// A subclass can modify the copied AST by placing modified copies of nodes
// onto the stack rather than direct copies.
//
// For example, imagine that you wanted to replace the table name of all tables
// in a query from A to B. Part of this can be achieved as follows:
//
//   1. Create a subclass of ResolvedASTDeepCopyVisitor.
//   2. Override
//      zetasql_base::Status VisitResolvedTableScan(const ResolvedTableScan *node);
//   3. Instead of the default behavior of pushing a copy of the node onto the
//      stack, push a modified copy, with the desired new table name.
//
// The consumer of the node pushed to the stack will see the modified version of
// the ResolvedTableScan, and will use that in the AST instead.
//
// There are two main ways to implement the Visit methods.
//
// METHOD 1 (preferred): Use the default method to make a copy, and then
//                       mutate it as appropriate.
//
//   This is preferred because it results in simpler code, automatically calls
//   the visitor on all child nodes and stitches them in, and automatically
//   copies all other flags and modifiers to the new node, without having to
//   call the constructor directly.  This method is the most robust against
//   future changes and additions to zetasql resolved node classes.
//
//   The example uses GetUnownedTopOfStack to modify the node in place.
//   The code could also use ConsumeRootNode to pop it from the stack and then
//   use PushNodeToStack to push a replacement.
//
//   Example:
//
//     zetasql_base::Status VisitResolvedTableScan(const ResolvedTableScan* node) {
//        const zetasql::Table* replacement_table = nullptr;
//        ZETASQL_RETURN_IF_ERROR(
//          catalog_->FindTable({replacement_table_name_}, &replacement_table));
//
//        // Make a copy using the default copy method.
//        ZETASQL_RETURN_IF_ERROR(CopyVisitResolvedTableScan(node));
//
//        // Mutate it so it points at the new table instead.
//        ResolvedTableScan* scan = GetUnownedTopOfStack<ResolvedTableScan>();
//        scan->set_table(replacement_table);
//
//        return ::zetasql_base::OkStatus();
//      }
//
// METHOD 2: Construct a replacement node directly.
//
//   This allows constructing different node types than the original tree had.
//   Calling node constructors directly means that this code will have to be
//   updated when new fields are added to zetasql nodes.
//
//     zetasql_base::Status VisitResolvedTableScan(const ResolvedTableScan* node) {
//        const zetasql::Table* replacement_table = nullptr;
//        ZETASQL_RETURN_IF_ERROR(
//          catalog_->FindTable({replacement_table_name_}, &replacement_table));
//
//        // Push a new unique_ptr of a newly-constructed table scan onto stack.
//        PushNodeToStack(MakeResolvedTableScan(
//            node->column_list(), replacement_table));
//
//        return ::zetasql_base::OkStatus();
//      }
//
//   If the copied node has any child nodes, those child nodes will also
//   need to be copied.  This can be done by invoking ProcessNode on each
//   child node, or by using the default Copy method and then releasing and
//   propagating each field individually, like this:
//
//     zetasql_base::Status VisitResolvedFilterScan(const ResolvedFilterScan* node) {
//       ZETASQL_RETURN_IF_ERROR(CopyVisitResolvedFilterScan(node));
//       auto filter_scan = ConsumeTopOfStack<ResolvedFilterScan>();
//
//       // This example just copies the node and its children, without
//       // changing anything.
//       PushNodeToStack(MakeResolvedFilterScan(
//           output_columns, filter_scan->release_input_scan(),
//           filter_scan->release_filter_expr()));
//       return ::zetasql_base::OkStatus();
//     }
//
// In both cases, we must ensure that all fields are deep-copied and that the
// modified node is pushed onto the stack after modification.
//
// Some full examples exist in resolved_ast_deep_copy_visitor_test.cc.
//
// Nodes need not be replaced on the stack with a node of the same kind, but
// the transformation must make sense in the context of the consumer of the
// copied node.
//
// For example, in the example in resolved_ast_deep_copy_visitor_test.cc, a
// ResolvedTableScan is replaced with a ResolvedFilterScan.
//
// Invoking the ResolvedASTDeepCopyVisitor subclass:
//
// The class is used like a regular ResolvedASTVisitor. Create an instance of
// the copier and call node->Accept(&copier). The output can then be consumed
// using copier.ConsumeRootNode().
//
// Example:
//
//   DerivedDeepCopyVisitor copier;
//   analyzer_output->resolved_statement()->Accept(&copier);
//   std::unique_ptr<ResolvedNode> copied_root_node =
//       copier.ConsumeRootNode<zetasql::ResolvedNode>());
//   // Do something with copied_root_node.
//
// Returns an error on unhandled node types. Reusable as long as no errors are
// returned and ConsumeRootNode is called every time.
//
// Not thread-safe.
class ResolvedASTDeepCopyVisitor : public ResolvedASTVisitor {
 public:
  ResolvedASTDeepCopyVisitor() = default;
  ResolvedASTDeepCopyVisitor(const ResolvedASTDeepCopyVisitor&) = delete;
  ResolvedASTDeepCopyVisitor& operator=(const ResolvedASTDeepCopyVisitor&) = delete;

  // Transfers the lone-remaining node on the stack to the caller on success.
  // This node must always be the root node, as no other node consumed it.
  // Node->Accept(&copier) must be called for this to be valid. See usage
  // and example comment above.
  template <typename ResolvedNodeType>
  zetasql_base::StatusOr<std::unique_ptr<ResolvedNodeType>> ConsumeRootNode() {
    ZETASQL_RET_CHECK_EQ(1, stack_.size());
    return ConsumeTopOfStack<ResolvedNodeType>();
  }

 protected:
  // Pushes a node onto the top of the stack. Used as an easy way to pass the
  // copied or modified node from the producer to the consumer. This should
  // always be called exactly once at or near the end of VisitResolvedX methods.
  void PushNodeToStack(std::unique_ptr<ResolvedNode> node) {
    stack_.push(std::move(node));
  }

  // Returns a pointer to the node at the top of the stack. Does not transfer
  // ownership nor modify the stack.
  // The stack must be non-empty for this to be valid.
  template <typename ResolvedNodeType>
  ResolvedNodeType* GetUnownedTopOfStack() const {
    DCHECK(!stack_.empty());
    return static_cast<ResolvedNodeType*>(stack_.top().get());
  }

  // Returns a unique pointer to the top of the stack, and removes it from
  // the top of the stack.
  template <typename ResolvedNodeType>
  std::unique_ptr<ResolvedNodeType> ConsumeTopOfStack() {
    DCHECK(!stack_.empty());
    std::unique_ptr<ResolvedNodeType> node(
        static_cast<ResolvedNodeType*>(stack_.top().release()));
    stack_.pop();
    return std::move(node);
  }

  // Calls Visit on the node, pops the result off of the stack, and returns it.
  template <typename ResolvedNodeType>
  zetasql_base::StatusOr<std::unique_ptr<ResolvedNodeType>> ProcessNode(
      const ResolvedNodeType* node) {
    DCHECK(stack_.empty());
    if (node == nullptr) {
      return std::unique_ptr<ResolvedNodeType>();
    }
    ZETASQL_RETURN_IF_ERROR(node->Accept(this));
    return ConsumeTopOfStack<ResolvedNodeType>();
  }

  // Calls ProcessNode for all nodes of a vector, and returns a new vector of the
  // processed nodes.
  template <typename ResolvedNodeType>
  zetasql_base::StatusOr<std::vector<std::unique_ptr<ResolvedNodeType>>>
  ProcessNodeList(
      const std::vector<std::unique_ptr<const ResolvedNodeType>>& node_list) {
    std::vector<std::unique_ptr<ResolvedNodeType>> output_node_list;
    output_node_list.reserve(node_list.size());
    for (const std::unique_ptr<const ResolvedNodeType>& node : node_list) {
      auto processed_node = ProcessNode<ResolvedNodeType>(node.get());
      ZETASQL_RETURN_IF_ERROR(processed_node.status());
      output_node_list.push_back(std::move(*processed_node));
    }
    return std::move(output_node_list);
  }

  // The following CopyVisitResolvedX functions create a deep copy of node
  // and push it onto the stack to be consumed. Given node must be non-null.
  zetasql_base::Status CopyVisitResolvedLiteral(
      const ResolvedLiteral* node);

  zetasql_base::Status CopyVisitResolvedParameter(
      const ResolvedParameter* node);

  zetasql_base::Status CopyVisitResolvedExpressionColumn(
      const ResolvedExpressionColumn* node);

  zetasql_base::Status CopyVisitResolvedColumnRef(
      const ResolvedColumnRef* node);

  zetasql_base::Status CopyVisitResolvedConstant(
      const ResolvedConstant* node);

  zetasql_base::Status CopyVisitResolvedFunctionCall(
      const ResolvedFunctionCall* node);

  zetasql_base::Status CopyVisitResolvedAggregateFunctionCall(
      const ResolvedAggregateFunctionCall* node);

  zetasql_base::Status CopyVisitResolvedAnalyticFunctionCall(
      const ResolvedAnalyticFunctionCall* node);

  zetasql_base::Status CopyVisitResolvedCast(
      const ResolvedCast* node);

  zetasql_base::Status CopyVisitResolvedMakeStruct(
      const ResolvedMakeStruct* node);

  zetasql_base::Status CopyVisitResolvedMakeProto(
      const ResolvedMakeProto* node);

  zetasql_base::Status CopyVisitResolvedMakeProtoField(
      const ResolvedMakeProtoField* node);

  zetasql_base::Status CopyVisitResolvedGetStructField(
      const ResolvedGetStructField* node);

  zetasql_base::Status CopyVisitResolvedGetProtoField(
      const ResolvedGetProtoField* node);

  zetasql_base::Status CopyVisitResolvedSubqueryExpr(
      const ResolvedSubqueryExpr* node);

  zetasql_base::Status CopyVisitResolvedModel(
      const ResolvedModel* node);

  zetasql_base::Status CopyVisitResolvedSingleRowScan(
      const ResolvedSingleRowScan* node);

  zetasql_base::Status CopyVisitResolvedTableScan(
      const ResolvedTableScan* node);

  zetasql_base::Status CopyVisitResolvedJoinScan(
      const ResolvedJoinScan* node);

  zetasql_base::Status CopyVisitResolvedArrayScan(
      const ResolvedArrayScan* node);

  zetasql_base::Status CopyVisitResolvedColumnHolder(
      const ResolvedColumnHolder* node);

  zetasql_base::Status CopyVisitResolvedFilterScan(
      const ResolvedFilterScan* node);

  zetasql_base::Status CopyVisitResolvedGroupingSet(
      const ResolvedGroupingSet* node);

  zetasql_base::Status CopyVisitResolvedAggregateScan(
      const ResolvedAggregateScan* node);

  zetasql_base::Status CopyVisitResolvedSetOperationItem(
      const ResolvedSetOperationItem* node);

  zetasql_base::Status CopyVisitResolvedSetOperationScan(
      const ResolvedSetOperationScan* node);

  zetasql_base::Status CopyVisitResolvedOrderByScan(
      const ResolvedOrderByScan* node);

  zetasql_base::Status CopyVisitResolvedLimitOffsetScan(
      const ResolvedLimitOffsetScan* node);

  zetasql_base::Status CopyVisitResolvedWithRefScan(
      const ResolvedWithRefScan* node);

  zetasql_base::Status CopyVisitResolvedAnalyticScan(
      const ResolvedAnalyticScan* node);

  zetasql_base::Status CopyVisitResolvedSampleScan(
      const ResolvedSampleScan* node);

  zetasql_base::Status CopyVisitResolvedComputedColumn(
      const ResolvedComputedColumn* node);

  zetasql_base::Status CopyVisitResolvedOrderByItem(
      const ResolvedOrderByItem* node);

  zetasql_base::Status CopyVisitResolvedColumnAnnotations(
      const ResolvedColumnAnnotations* node);

  zetasql_base::Status CopyVisitResolvedGeneratedColumnInfo(
      const ResolvedGeneratedColumnInfo* node);

  zetasql_base::Status CopyVisitResolvedColumnDefinition(
      const ResolvedColumnDefinition* node);

  zetasql_base::Status CopyVisitResolvedPrimaryKey(
      const ResolvedPrimaryKey* node);

  zetasql_base::Status CopyVisitResolvedForeignKey(
      const ResolvedForeignKey* node);

  zetasql_base::Status CopyVisitResolvedCheckConstraint(
      const ResolvedCheckConstraint* node);

  zetasql_base::Status CopyVisitResolvedOutputColumn(
      const ResolvedOutputColumn* node);

  zetasql_base::Status CopyVisitResolvedProjectScan(
      const ResolvedProjectScan* node);

  zetasql_base::Status CopyVisitResolvedTVFScan(
      const ResolvedTVFScan* node);

  zetasql_base::Status CopyVisitResolvedTVFArgument(
      const ResolvedTVFArgument* node);

  zetasql_base::Status CopyVisitResolvedExplainStmt(
      const ResolvedExplainStmt* node);

  zetasql_base::Status CopyVisitResolvedQueryStmt(
      const ResolvedQueryStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateDatabaseStmt(
      const ResolvedCreateDatabaseStmt* node);

  zetasql_base::Status CopyVisitResolvedIndexItem(
      const ResolvedIndexItem* node);

  zetasql_base::Status CopyVisitResolvedUnnestItem(
      const ResolvedUnnestItem* node);

  zetasql_base::Status CopyVisitResolvedCreateIndexStmt(
      const ResolvedCreateIndexStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateTableStmt(
      const ResolvedCreateTableStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateTableAsSelectStmt(
      const ResolvedCreateTableAsSelectStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateModelStmt(
      const ResolvedCreateModelStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateViewStmt(
      const ResolvedCreateViewStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateExternalTableStmt(
      const ResolvedCreateExternalTableStmt* node);

  zetasql_base::Status CopyVisitResolvedExportDataStmt(
      const ResolvedExportDataStmt* node);

  zetasql_base::Status CopyVisitResolvedDefineTableStmt(
      const ResolvedDefineTableStmt* node);

  zetasql_base::Status CopyVisitResolvedDescribeStmt(
      const ResolvedDescribeStmt* node);

  zetasql_base::Status CopyVisitResolvedShowStmt(
      const ResolvedShowStmt* node);

  zetasql_base::Status CopyVisitResolvedBeginStmt(
      const ResolvedBeginStmt* node);

  zetasql_base::Status CopyVisitResolvedSetTransactionStmt(
      const ResolvedSetTransactionStmt* node);

  zetasql_base::Status CopyVisitResolvedCommitStmt(
      const ResolvedCommitStmt* node);

  zetasql_base::Status CopyVisitResolvedRollbackStmt(
      const ResolvedRollbackStmt* node);

  zetasql_base::Status CopyVisitResolvedStartBatchStmt(
      const ResolvedStartBatchStmt* node);

  zetasql_base::Status CopyVisitResolvedRunBatchStmt(
      const ResolvedRunBatchStmt* node);

  zetasql_base::Status CopyVisitResolvedAbortBatchStmt(
      const ResolvedAbortBatchStmt* node);

  zetasql_base::Status CopyVisitResolvedDropStmt(
      const ResolvedDropStmt* node);

  zetasql_base::Status CopyVisitResolvedDropMaterializedViewStmt(
      const ResolvedDropMaterializedViewStmt* node);

  zetasql_base::Status CopyVisitResolvedWithScan(
      const ResolvedWithScan* node);

  zetasql_base::Status CopyVisitResolvedWithEntry(
      const ResolvedWithEntry* node);

  zetasql_base::Status CopyVisitResolvedOption(
      const ResolvedOption* node);

  zetasql_base::Status CopyVisitResolvedWindowPartitioning(
      const ResolvedWindowPartitioning* node);

  zetasql_base::Status CopyVisitResolvedWindowOrdering(
      const ResolvedWindowOrdering* node);

  zetasql_base::Status CopyVisitResolvedWindowFrame(
      const ResolvedWindowFrame* node);

  zetasql_base::Status CopyVisitResolvedAnalyticFunctionGroup(
      const ResolvedAnalyticFunctionGroup* node);

  zetasql_base::Status CopyVisitResolvedWindowFrameExpr(
      const ResolvedWindowFrameExpr* node);

  zetasql_base::Status CopyVisitResolvedDMLValue(
      const ResolvedDMLValue* node);

  zetasql_base::Status CopyVisitResolvedDMLDefault(
      const ResolvedDMLDefault* node);

  zetasql_base::Status CopyVisitResolvedAssertStmt(
      const ResolvedAssertStmt* node);

  zetasql_base::Status CopyVisitResolvedAssertRowsModified(
      const ResolvedAssertRowsModified* node);

  zetasql_base::Status CopyVisitResolvedInsertRow(
      const ResolvedInsertRow* node);

  zetasql_base::Status CopyVisitResolvedInsertStmt(
      const ResolvedInsertStmt* node);

  zetasql_base::Status CopyVisitResolvedDeleteStmt(
      const ResolvedDeleteStmt* node);

  zetasql_base::Status CopyVisitResolvedUpdateItem(
      const ResolvedUpdateItem* node);

  zetasql_base::Status CopyVisitResolvedUpdateArrayItem(
      const ResolvedUpdateArrayItem* node);

  zetasql_base::Status CopyVisitResolvedUpdateStmt(
      const ResolvedUpdateStmt* node);

  zetasql_base::Status CopyVisitResolvedMergeWhen(
      const ResolvedMergeWhen* node);

  zetasql_base::Status CopyVisitResolvedMergeStmt(
      const ResolvedMergeStmt* node);

  zetasql_base::Status CopyVisitResolvedPrivilege(
      const ResolvedPrivilege* node);

  zetasql_base::Status CopyVisitResolvedGrantStmt(
      const ResolvedGrantStmt* node);

  zetasql_base::Status CopyVisitResolvedRevokeStmt(
      const ResolvedRevokeStmt* node);

  zetasql_base::Status CopyVisitResolvedAlterMaterializedViewStmt(
      const ResolvedAlterMaterializedViewStmt* node);

  zetasql_base::Status CopyVisitResolvedAlterTableStmt(
      const ResolvedAlterTableStmt* node);

  zetasql_base::Status CopyVisitResolvedAlterViewStmt(
      const ResolvedAlterViewStmt* node);

  zetasql_base::Status CopyVisitResolvedSetOptionsAction(
      const ResolvedSetOptionsAction* node);

  zetasql_base::Status CopyVisitResolvedAlterTableSetOptionsStmt(
      const ResolvedAlterTableSetOptionsStmt* node);

  zetasql_base::Status CopyVisitResolvedRenameStmt(
      const ResolvedRenameStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateRowPolicyStmt(
      const ResolvedCreateRowPolicyStmt* node);

  zetasql_base::Status CopyVisitResolvedDropRowPolicyStmt(
      const ResolvedDropRowPolicyStmt* node);

  zetasql_base::Status CopyVisitResolvedAlterRowPolicyStmt(
      const ResolvedAlterRowPolicyStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateConstantStmt(
      const ResolvedCreateConstantStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateFunctionStmt(
      const ResolvedCreateFunctionStmt* node);

  zetasql_base::Status CopyVisitResolvedArgumentDef(
      const ResolvedArgumentDef* node);

  zetasql_base::Status CopyVisitResolvedArgumentRef(
      const ResolvedArgumentRef* node);

  zetasql_base::Status CopyVisitResolvedCreateTableFunctionStmt(
      const ResolvedCreateTableFunctionStmt* node);

  zetasql_base::Status CopyVisitResolvedRelationArgumentScan(
      const ResolvedRelationArgumentScan* node);

  zetasql_base::Status CopyVisitResolvedArgumentList(
      const ResolvedArgumentList* node);

  zetasql_base::Status CopyVisitResolvedFunctionSignatureHolder(
      const ResolvedFunctionSignatureHolder* node);

  zetasql_base::Status CopyVisitResolvedDropFunctionStmt(
      const ResolvedDropFunctionStmt* node);

  zetasql_base::Status CopyVisitResolvedCallStmt(
      const ResolvedCallStmt* node);

  zetasql_base::Status CopyVisitResolvedImportStmt(
      const ResolvedImportStmt* node);

  zetasql_base::Status CopyVisitResolvedModuleStmt(
      const ResolvedModuleStmt* node);

  zetasql_base::Status CopyVisitResolvedAggregateHavingModifier(
      const ResolvedAggregateHavingModifier* node);

  zetasql_base::Status CopyVisitResolvedCreateMaterializedViewStmt(
      const ResolvedCreateMaterializedViewStmt* node);

  zetasql_base::Status CopyVisitResolvedCreateProcedureStmt(
      const ResolvedCreateProcedureStmt* node);

  zetasql_base::Status DefaultVisit(const ResolvedNode* node) override;

  // The individual visit methods for each of the node types. We will copy
  // and visit each of the nodes.
  zetasql_base::Status VisitResolvedLiteral(
      const ResolvedLiteral* node) override;

  zetasql_base::Status VisitResolvedParameter(
      const ResolvedParameter* node) override;

  zetasql_base::Status VisitResolvedExpressionColumn(
      const ResolvedExpressionColumn* node) override;

  zetasql_base::Status VisitResolvedColumnRef(
      const ResolvedColumnRef* node) override;

  zetasql_base::Status VisitResolvedConstant(
      const ResolvedConstant* node) override;

  zetasql_base::Status VisitResolvedFunctionCall(
      const ResolvedFunctionCall* node) override;

  zetasql_base::Status VisitResolvedAggregateFunctionCall(
      const ResolvedAggregateFunctionCall* node) override;

  zetasql_base::Status VisitResolvedAnalyticFunctionCall(
      const ResolvedAnalyticFunctionCall* node) override;

  zetasql_base::Status VisitResolvedCast(
      const ResolvedCast* node) override;

  zetasql_base::Status VisitResolvedMakeStruct(
      const ResolvedMakeStruct* node) override;

  zetasql_base::Status VisitResolvedMakeProto(
      const ResolvedMakeProto* node) override;

  zetasql_base::Status VisitResolvedMakeProtoField(
      const ResolvedMakeProtoField* node) override;

  zetasql_base::Status VisitResolvedGetStructField(
      const ResolvedGetStructField* node) override;

  zetasql_base::Status VisitResolvedGetProtoField(
      const ResolvedGetProtoField* node) override;

  zetasql_base::Status VisitResolvedSubqueryExpr(
      const ResolvedSubqueryExpr* node) override;

  zetasql_base::Status VisitResolvedModel(
      const ResolvedModel* node) override;

  zetasql_base::Status VisitResolvedSingleRowScan(
      const ResolvedSingleRowScan* node) override;

  zetasql_base::Status VisitResolvedTableScan(
      const ResolvedTableScan* node) override;

  zetasql_base::Status VisitResolvedJoinScan(
      const ResolvedJoinScan* node) override;

  zetasql_base::Status VisitResolvedArrayScan(
      const ResolvedArrayScan* node) override;

  zetasql_base::Status VisitResolvedColumnHolder(
      const ResolvedColumnHolder* node) override;

  zetasql_base::Status VisitResolvedFilterScan(
      const ResolvedFilterScan* node) override;

  zetasql_base::Status VisitResolvedGroupingSet(
      const ResolvedGroupingSet* node) override;

  zetasql_base::Status VisitResolvedAggregateScan(
      const ResolvedAggregateScan* node) override;

  zetasql_base::Status VisitResolvedSetOperationItem(
      const ResolvedSetOperationItem* node) override;

  zetasql_base::Status VisitResolvedSetOperationScan(
      const ResolvedSetOperationScan* node) override;

  zetasql_base::Status VisitResolvedOrderByScan(
      const ResolvedOrderByScan* node) override;

  zetasql_base::Status VisitResolvedLimitOffsetScan(
      const ResolvedLimitOffsetScan* node) override;

  zetasql_base::Status VisitResolvedWithRefScan(
      const ResolvedWithRefScan* node) override;

  zetasql_base::Status VisitResolvedAnalyticScan(
      const ResolvedAnalyticScan* node) override;

  zetasql_base::Status VisitResolvedSampleScan(
      const ResolvedSampleScan* node) override;

  zetasql_base::Status VisitResolvedComputedColumn(
      const ResolvedComputedColumn* node) override;

  zetasql_base::Status VisitResolvedOrderByItem(
      const ResolvedOrderByItem* node) override;

  zetasql_base::Status VisitResolvedColumnAnnotations(
      const ResolvedColumnAnnotations* node) override;

  zetasql_base::Status VisitResolvedGeneratedColumnInfo(
      const ResolvedGeneratedColumnInfo* node) override;

  zetasql_base::Status VisitResolvedColumnDefinition(
      const ResolvedColumnDefinition* node) override;

  zetasql_base::Status VisitResolvedPrimaryKey(
      const ResolvedPrimaryKey* node) override;

  zetasql_base::Status VisitResolvedForeignKey(
      const ResolvedForeignKey* node) override;

  zetasql_base::Status VisitResolvedCheckConstraint(
      const ResolvedCheckConstraint* node) override;

  zetasql_base::Status VisitResolvedOutputColumn(
      const ResolvedOutputColumn* node) override;

  zetasql_base::Status VisitResolvedProjectScan(
      const ResolvedProjectScan* node) override;

  zetasql_base::Status VisitResolvedTVFScan(
      const ResolvedTVFScan* node) override;

  zetasql_base::Status VisitResolvedTVFArgument(
      const ResolvedTVFArgument* node) override;

  zetasql_base::Status VisitResolvedExplainStmt(
      const ResolvedExplainStmt* node) override;

  zetasql_base::Status VisitResolvedQueryStmt(
      const ResolvedQueryStmt* node) override;

  zetasql_base::Status VisitResolvedCreateDatabaseStmt(
      const ResolvedCreateDatabaseStmt* node) override;

  zetasql_base::Status VisitResolvedIndexItem(
      const ResolvedIndexItem* node) override;

  zetasql_base::Status VisitResolvedUnnestItem(
      const ResolvedUnnestItem* node) override;

  zetasql_base::Status VisitResolvedCreateIndexStmt(
      const ResolvedCreateIndexStmt* node) override;

  zetasql_base::Status VisitResolvedCreateTableStmt(
      const ResolvedCreateTableStmt* node) override;

  zetasql_base::Status VisitResolvedCreateTableAsSelectStmt(
      const ResolvedCreateTableAsSelectStmt* node) override;

  zetasql_base::Status VisitResolvedCreateModelStmt(
      const ResolvedCreateModelStmt* node) override;

  zetasql_base::Status VisitResolvedCreateViewStmt(
      const ResolvedCreateViewStmt* node) override;

  zetasql_base::Status VisitResolvedCreateExternalTableStmt(
      const ResolvedCreateExternalTableStmt* node) override;

  zetasql_base::Status VisitResolvedExportDataStmt(
      const ResolvedExportDataStmt* node) override;

  zetasql_base::Status VisitResolvedDefineTableStmt(
      const ResolvedDefineTableStmt* node) override;

  zetasql_base::Status VisitResolvedDescribeStmt(
      const ResolvedDescribeStmt* node) override;

  zetasql_base::Status VisitResolvedShowStmt(
      const ResolvedShowStmt* node) override;

  zetasql_base::Status VisitResolvedBeginStmt(
      const ResolvedBeginStmt* node) override;

  zetasql_base::Status VisitResolvedSetTransactionStmt(
      const ResolvedSetTransactionStmt* node) override;

  zetasql_base::Status VisitResolvedCommitStmt(
      const ResolvedCommitStmt* node) override;

  zetasql_base::Status VisitResolvedRollbackStmt(
      const ResolvedRollbackStmt* node) override;

  zetasql_base::Status VisitResolvedStartBatchStmt(
      const ResolvedStartBatchStmt* node) override;

  zetasql_base::Status VisitResolvedRunBatchStmt(
      const ResolvedRunBatchStmt* node) override;

  zetasql_base::Status VisitResolvedAbortBatchStmt(
      const ResolvedAbortBatchStmt* node) override;

  zetasql_base::Status VisitResolvedDropStmt(
      const ResolvedDropStmt* node) override;

  zetasql_base::Status VisitResolvedDropMaterializedViewStmt(
      const ResolvedDropMaterializedViewStmt* node) override;

  zetasql_base::Status VisitResolvedWithScan(
      const ResolvedWithScan* node) override;

  zetasql_base::Status VisitResolvedWithEntry(
      const ResolvedWithEntry* node) override;

  zetasql_base::Status VisitResolvedOption(
      const ResolvedOption* node) override;

  zetasql_base::Status VisitResolvedWindowPartitioning(
      const ResolvedWindowPartitioning* node) override;

  zetasql_base::Status VisitResolvedWindowOrdering(
      const ResolvedWindowOrdering* node) override;

  zetasql_base::Status VisitResolvedWindowFrame(
      const ResolvedWindowFrame* node) override;

  zetasql_base::Status VisitResolvedAnalyticFunctionGroup(
      const ResolvedAnalyticFunctionGroup* node) override;

  zetasql_base::Status VisitResolvedWindowFrameExpr(
      const ResolvedWindowFrameExpr* node) override;

  zetasql_base::Status VisitResolvedDMLValue(
      const ResolvedDMLValue* node) override;

  zetasql_base::Status VisitResolvedDMLDefault(
      const ResolvedDMLDefault* node) override;

  zetasql_base::Status VisitResolvedAssertStmt(
      const ResolvedAssertStmt* node) override;

  zetasql_base::Status VisitResolvedAssertRowsModified(
      const ResolvedAssertRowsModified* node) override;

  zetasql_base::Status VisitResolvedInsertRow(
      const ResolvedInsertRow* node) override;

  zetasql_base::Status VisitResolvedInsertStmt(
      const ResolvedInsertStmt* node) override;

  zetasql_base::Status VisitResolvedDeleteStmt(
      const ResolvedDeleteStmt* node) override;

  zetasql_base::Status VisitResolvedUpdateItem(
      const ResolvedUpdateItem* node) override;

  zetasql_base::Status VisitResolvedUpdateArrayItem(
      const ResolvedUpdateArrayItem* node) override;

  zetasql_base::Status VisitResolvedUpdateStmt(
      const ResolvedUpdateStmt* node) override;

  zetasql_base::Status VisitResolvedMergeWhen(
      const ResolvedMergeWhen* node) override;

  zetasql_base::Status VisitResolvedMergeStmt(
      const ResolvedMergeStmt* node) override;

  zetasql_base::Status VisitResolvedPrivilege(
      const ResolvedPrivilege* node) override;

  zetasql_base::Status VisitResolvedGrantStmt(
      const ResolvedGrantStmt* node) override;

  zetasql_base::Status VisitResolvedRevokeStmt(
      const ResolvedRevokeStmt* node) override;

  zetasql_base::Status VisitResolvedAlterMaterializedViewStmt(
      const ResolvedAlterMaterializedViewStmt* node) override;

  zetasql_base::Status VisitResolvedAlterTableStmt(
      const ResolvedAlterTableStmt* node) override;

  zetasql_base::Status VisitResolvedAlterViewStmt(
      const ResolvedAlterViewStmt* node) override;

  zetasql_base::Status VisitResolvedSetOptionsAction(
      const ResolvedSetOptionsAction* node) override;

  zetasql_base::Status VisitResolvedAlterTableSetOptionsStmt(
      const ResolvedAlterTableSetOptionsStmt* node) override;

  zetasql_base::Status VisitResolvedRenameStmt(
      const ResolvedRenameStmt* node) override;

  zetasql_base::Status VisitResolvedCreateRowPolicyStmt(
      const ResolvedCreateRowPolicyStmt* node) override;

  zetasql_base::Status VisitResolvedDropRowPolicyStmt(
      const ResolvedDropRowPolicyStmt* node) override;

  zetasql_base::Status VisitResolvedAlterRowPolicyStmt(
      const ResolvedAlterRowPolicyStmt* node) override;

  zetasql_base::Status VisitResolvedCreateConstantStmt(
      const ResolvedCreateConstantStmt* node) override;

  zetasql_base::Status VisitResolvedCreateFunctionStmt(
      const ResolvedCreateFunctionStmt* node) override;

  zetasql_base::Status VisitResolvedArgumentDef(
      const ResolvedArgumentDef* node) override;

  zetasql_base::Status VisitResolvedArgumentRef(
      const ResolvedArgumentRef* node) override;

  zetasql_base::Status VisitResolvedCreateTableFunctionStmt(
      const ResolvedCreateTableFunctionStmt* node) override;

  zetasql_base::Status VisitResolvedRelationArgumentScan(
      const ResolvedRelationArgumentScan* node) override;

  zetasql_base::Status VisitResolvedArgumentList(
      const ResolvedArgumentList* node) override;

  zetasql_base::Status VisitResolvedFunctionSignatureHolder(
      const ResolvedFunctionSignatureHolder* node) override;

  zetasql_base::Status VisitResolvedDropFunctionStmt(
      const ResolvedDropFunctionStmt* node) override;

  zetasql_base::Status VisitResolvedCallStmt(
      const ResolvedCallStmt* node) override;

  zetasql_base::Status VisitResolvedImportStmt(
      const ResolvedImportStmt* node) override;

  zetasql_base::Status VisitResolvedModuleStmt(
      const ResolvedModuleStmt* node) override;

  zetasql_base::Status VisitResolvedAggregateHavingModifier(
      const ResolvedAggregateHavingModifier* node) override;

  zetasql_base::Status VisitResolvedCreateMaterializedViewStmt(
      const ResolvedCreateMaterializedViewStmt* node) override;

  zetasql_base::Status VisitResolvedCreateProcedureStmt(
      const ResolvedCreateProcedureStmt* node) override;

 private:
  // Copies the hint list from the original node to the copied node. This is
  // required, as hint_list is not a constructor arg, and the only way to
  // transfer ownership is to explicitly set it after constructing the copy.
  template <typename ResolvedNodeType> zetasql_base::Status CopyHintList(
      const ResolvedNodeType *from, ResolvedNodeType *to) {
    for (const std::unique_ptr<const zetasql::ResolvedOption>& hint :
        from->hint_list()) {
      ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<zetasql::ResolvedOption> copied_hint,
                       ProcessNode(hint.get()));
      to->add_hint_list(std::move(copied_hint));
    }
    return ::zetasql_base::OkStatus();
  }

  // The stack is used for making the recursive copying work:
  // 1. A copied node is pushed to the stack before the VisitX function returns.
  // 2. The consuming VisitX functions (the one calling node_x->Accept())
  //    takes it from the stack.
  // 3. The entire copied tree is available using ConsumeRootNode() in the end.
  std::stack<std::unique_ptr<ResolvedNode>> stack_;
};

}  // namespace zetasql

#endif  // ZETASQL_RESOLVED_AST_RESOLVED_AST_DEEP_COPY_VISITOR_H_