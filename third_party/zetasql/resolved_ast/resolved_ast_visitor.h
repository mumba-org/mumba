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

// resolved_ast_visitor.h GENERATED FROM resolved_ast_visitor.h.template
#ifndef ZETASQL_RESOLVED_AST_RESOLVED_AST_VISITOR_H_
#define ZETASQL_RESOLVED_AST_RESOLVED_AST_VISITOR_H_

#include "zetasql/resolved_ast/resolved_ast.h"
#include "zetasql/resolved_ast/resolved_node.h"
#include "zetasql/resolved_ast/resolved_column.h"
#include "zetasql/base/status.h"

namespace zetasql {

class ResolvedASTVisitor {
 public:
  ResolvedASTVisitor() {}
  ResolvedASTVisitor(const ResolvedASTVisitor&) = delete;
  ResolvedASTVisitor& operator=(const ResolvedASTVisitor&) = delete;
  virtual ~ResolvedASTVisitor() {}

  // This is the default visit method called for any node that doesn't have an
  // override for the node specific Visit... method.
  // Users may want to override this to change traversal order, give errors on
  // unhandled nodes or stop traversing after errors.
  //
  // The default implementation just visits the child nodes recursively.
  // Children of a node are visited in an undefined order.
  virtual zetasql_base::Status DefaultVisit(const ResolvedNode* node) {
    return node->ChildrenAccept(this);
  }

  virtual zetasql_base::Status VisitResolvedArgument(const ResolvedArgument* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedExpr(const ResolvedExpr* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedLiteral(const ResolvedLiteral* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedParameter(const ResolvedParameter* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedExpressionColumn(const ResolvedExpressionColumn* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedColumnRef(const ResolvedColumnRef* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedConstant(const ResolvedConstant* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedFunctionCallBase(const ResolvedFunctionCallBase* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedFunctionCall(const ResolvedFunctionCall* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedNonScalarFunctionCallBase(const ResolvedNonScalarFunctionCallBase* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAggregateFunctionCall(const ResolvedAggregateFunctionCall* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAnalyticFunctionCall(const ResolvedAnalyticFunctionCall* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCast(const ResolvedCast* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedMakeStruct(const ResolvedMakeStruct* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedMakeProto(const ResolvedMakeProto* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedMakeProtoField(const ResolvedMakeProtoField* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGetStructField(const ResolvedGetStructField* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGetProtoField(const ResolvedGetProtoField* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSubqueryExpr(const ResolvedSubqueryExpr* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedScan(const ResolvedScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedModel(const ResolvedModel* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSingleRowScan(const ResolvedSingleRowScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedTableScan(const ResolvedTableScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedJoinScan(const ResolvedJoinScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedArrayScan(const ResolvedArrayScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedColumnHolder(const ResolvedColumnHolder* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedFilterScan(const ResolvedFilterScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGroupingSet(const ResolvedGroupingSet* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAggregateScanBase(const ResolvedAggregateScanBase* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAggregateScan(const ResolvedAggregateScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSetOperationItem(const ResolvedSetOperationItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSetOperationScan(const ResolvedSetOperationScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedOrderByScan(const ResolvedOrderByScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedLimitOffsetScan(const ResolvedLimitOffsetScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWithRefScan(const ResolvedWithRefScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAnalyticScan(const ResolvedAnalyticScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSampleScan(const ResolvedSampleScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedComputedColumn(const ResolvedComputedColumn* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedOrderByItem(const ResolvedOrderByItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedColumnAnnotations(const ResolvedColumnAnnotations* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGeneratedColumnInfo(const ResolvedGeneratedColumnInfo* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedColumnDefinition(const ResolvedColumnDefinition* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedPrimaryKey(const ResolvedPrimaryKey* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedForeignKey(const ResolvedForeignKey* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCheckConstraint(const ResolvedCheckConstraint* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedOutputColumn(const ResolvedOutputColumn* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedProjectScan(const ResolvedProjectScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedTVFScan(const ResolvedTVFScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedTVFArgument(const ResolvedTVFArgument* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedStatement(const ResolvedStatement* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedExplainStmt(const ResolvedExplainStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedQueryStmt(const ResolvedQueryStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateDatabaseStmt(const ResolvedCreateDatabaseStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateStatement(const ResolvedCreateStatement* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedIndexItem(const ResolvedIndexItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedUnnestItem(const ResolvedUnnestItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateIndexStmt(const ResolvedCreateIndexStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateTableStmtBase(const ResolvedCreateTableStmtBase* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateTableStmt(const ResolvedCreateTableStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateTableAsSelectStmt(const ResolvedCreateTableAsSelectStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateModelStmt(const ResolvedCreateModelStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateViewBase(const ResolvedCreateViewBase* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateViewStmt(const ResolvedCreateViewStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateExternalTableStmt(const ResolvedCreateExternalTableStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedExportDataStmt(const ResolvedExportDataStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDefineTableStmt(const ResolvedDefineTableStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDescribeStmt(const ResolvedDescribeStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedShowStmt(const ResolvedShowStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedBeginStmt(const ResolvedBeginStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSetTransactionStmt(const ResolvedSetTransactionStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCommitStmt(const ResolvedCommitStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedRollbackStmt(const ResolvedRollbackStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedStartBatchStmt(const ResolvedStartBatchStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedRunBatchStmt(const ResolvedRunBatchStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAbortBatchStmt(const ResolvedAbortBatchStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDropStmt(const ResolvedDropStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDropMaterializedViewStmt(const ResolvedDropMaterializedViewStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWithScan(const ResolvedWithScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWithEntry(const ResolvedWithEntry* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedOption(const ResolvedOption* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWindowPartitioning(const ResolvedWindowPartitioning* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWindowOrdering(const ResolvedWindowOrdering* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWindowFrame(const ResolvedWindowFrame* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAnalyticFunctionGroup(const ResolvedAnalyticFunctionGroup* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedWindowFrameExpr(const ResolvedWindowFrameExpr* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDMLValue(const ResolvedDMLValue* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDMLDefault(const ResolvedDMLDefault* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAssertStmt(const ResolvedAssertStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAssertRowsModified(const ResolvedAssertRowsModified* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedInsertRow(const ResolvedInsertRow* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedInsertStmt(const ResolvedInsertStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDeleteStmt(const ResolvedDeleteStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedUpdateItem(const ResolvedUpdateItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedUpdateArrayItem(const ResolvedUpdateArrayItem* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedUpdateStmt(const ResolvedUpdateStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedMergeWhen(const ResolvedMergeWhen* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedMergeStmt(const ResolvedMergeStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedPrivilege(const ResolvedPrivilege* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGrantOrRevokeStmt(const ResolvedGrantOrRevokeStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedGrantStmt(const ResolvedGrantStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedRevokeStmt(const ResolvedRevokeStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterObjectStmt(const ResolvedAlterObjectStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterMaterializedViewStmt(const ResolvedAlterMaterializedViewStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterTableStmt(const ResolvedAlterTableStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterViewStmt(const ResolvedAlterViewStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterAction(const ResolvedAlterAction* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedSetOptionsAction(const ResolvedSetOptionsAction* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterTableSetOptionsStmt(const ResolvedAlterTableSetOptionsStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedRenameStmt(const ResolvedRenameStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateRowPolicyStmt(const ResolvedCreateRowPolicyStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDropRowPolicyStmt(const ResolvedDropRowPolicyStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAlterRowPolicyStmt(const ResolvedAlterRowPolicyStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateConstantStmt(const ResolvedCreateConstantStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateFunctionStmt(const ResolvedCreateFunctionStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedArgumentDef(const ResolvedArgumentDef* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedArgumentRef(const ResolvedArgumentRef* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateTableFunctionStmt(const ResolvedCreateTableFunctionStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedRelationArgumentScan(const ResolvedRelationArgumentScan* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedArgumentList(const ResolvedArgumentList* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedFunctionSignatureHolder(const ResolvedFunctionSignatureHolder* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedDropFunctionStmt(const ResolvedDropFunctionStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCallStmt(const ResolvedCallStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedImportStmt(const ResolvedImportStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedModuleStmt(const ResolvedModuleStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedAggregateHavingModifier(const ResolvedAggregateHavingModifier* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateMaterializedViewStmt(const ResolvedCreateMaterializedViewStmt* node) {
    return DefaultVisit(node);
  }
  virtual zetasql_base::Status VisitResolvedCreateProcedureStmt(const ResolvedCreateProcedureStmt* node) {
    return DefaultVisit(node);
  }
};

}  // namespace zetasql

#endif  // ZETASQL_RESOLVED_AST_RESOLVED_AST_VISITOR_H_