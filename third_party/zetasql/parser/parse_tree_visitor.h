#ifndef STORAGE_ZETASQL_PARSER_PARSE_TREE_VISITOR_H_
#define STORAGE_ZETASQL_PARSER_PARSE_TREE_VISITOR_H_
#include "zetasql/parser/parse_tree.h"

namespace zetasql {
class ParseTreeVisitor {
 public:
  virtual ~ParseTreeVisitor() {}
  virtual void visit(const ASTNode *node, void* data) = 0;
  virtual void visitASTHintedStatement(const ASTHintedStatement* node, void* data) = 0;

  virtual void visitASTExplainStatement(const ASTExplainStatement* node, void* data) = 0;

  virtual void visitASTDescribeStatement(const ASTDescribeStatement* node, void* data) = 0;

  virtual void visitASTShowStatement(const ASTShowStatement* node, void* data) = 0;

  virtual void visitASTTransactionIsolationLevel(const ASTTransactionIsolationLevel* node, void* data) = 0;

  virtual void visitASTTransactionReadWriteMode(const ASTTransactionReadWriteMode* node, void* data) = 0;

  virtual void visitASTTransactionModeList(const ASTTransactionModeList* node, void* data) = 0;

  virtual void visitASTBeginStatement(const ASTBeginStatement* node, void* data) = 0;

  virtual void visitASTSetTransactionStatement(const ASTSetTransactionStatement* node, void* data) = 0;

  virtual void visitASTCommitStatement(const ASTCommitStatement* node, void* data) = 0;

  virtual void visitASTRollbackStatement(const ASTRollbackStatement* node, void* data) = 0;

  virtual void visitASTStartBatchStatement(const ASTStartBatchStatement* node, void* data) = 0;

  virtual void visitASTRunBatchStatement(const ASTRunBatchStatement* node, void* data) = 0;

  virtual void visitASTAbortBatchStatement(const ASTAbortBatchStatement* node, void* data) = 0;

  virtual void visitASTDropStatement(const ASTDropStatement* node, void* data) = 0;

  virtual void visitASTDropFunctionStatement(const ASTDropFunctionStatement* node, void* data) = 0;

  virtual void visitASTDropRowPolicyStatement(const ASTDropRowPolicyStatement* node, void* data) = 0;

  virtual void visitASTDropAllRowPoliciesStatement(const ASTDropAllRowPoliciesStatement* node, void* data) = 0;

  virtual void visitASTDropMaterializedViewStatement(const ASTDropMaterializedViewStatement* node, void* data) = 0;

  virtual void visitASTRenameStatement(const ASTRenameStatement* node, void* data) = 0;

  virtual void visitASTImportStatement(const ASTImportStatement* node, void* data) = 0;

  virtual void visitASTModuleStatement(const ASTModuleStatement* node, void* data) = 0;

  virtual void visitASTQueryStatement(const ASTQueryStatement* node, void* data) = 0;

  virtual void visitASTWithClause(const ASTWithClause* node, void* data) = 0;

  virtual void visitASTWithClauseEntry(const ASTWithClauseEntry* node, void* data) = 0;

  virtual void visitASTQuery(const ASTQuery* node, void* data) = 0;

  virtual void visitASTSetOperation(const ASTSetOperation* node, void* data) = 0;

  virtual void visitASTSelect(const ASTSelect* node, void* data) = 0;

  virtual void visitASTSelectAs(const ASTSelectAs* node, void* data) = 0;

  virtual void visitASTSelectList(const ASTSelectList* node, void* data) = 0;

  virtual void visitASTSelectColumn(const ASTSelectColumn* node, void* data) = 0;

  virtual void visitASTAlias(const ASTAlias* node, void* data) = 0;

  virtual void visitASTIntoAlias(const ASTIntoAlias* node, void* data) = 0;

  virtual void visitASTFromClause(const ASTFromClause* node, void* data) = 0;

  virtual void visitASTWindowClause(const ASTWindowClause* node, void* data) = 0;

  virtual void visitASTUnnestExpression(const ASTUnnestExpression* node, void* data) = 0;

  virtual void visitASTWithOffset(const ASTWithOffset* node, void* data) = 0;

  virtual void visitASTUnnestExpressionWithOptAliasAndOffset(const ASTUnnestExpressionWithOptAliasAndOffset* node, void* data) = 0;

  virtual void visitASTTablePathExpression(const ASTTablePathExpression* node, void* data) = 0;

  virtual void visitASTTableSubquery(const ASTTableSubquery* node, void* data) = 0;

  virtual void visitASTJoin(const ASTJoin* node, void* data) = 0;

  virtual void visitASTParenthesizedJoin(const ASTParenthesizedJoin* node, void* data) = 0;

  virtual void visitASTOnClause(const ASTOnClause* node, void* data) = 0;

  virtual void visitASTUsingClause(const ASTUsingClause* node, void* data) = 0;

  virtual void visitASTWhereClause(const ASTWhereClause* node, void* data) = 0;

  virtual void visitASTRollup(const ASTRollup* node, void* data) = 0;

  virtual void visitASTForSystemTime(const ASTForSystemTime* node, void* data) = 0;

  virtual void visitASTGroupingItem(const ASTGroupingItem* node, void* data) = 0;

  virtual void visitASTGroupBy(const ASTGroupBy* node, void* data) = 0;

  virtual void visitASTHaving(const ASTHaving* node, void* data) = 0;

  virtual void visitASTCollate(const ASTCollate* node, void* data) = 0;

  virtual void visitASTOrderingExpression(const ASTOrderingExpression* node, void* data) = 0;

  virtual void visitASTOrderBy(const ASTOrderBy* node, void* data) = 0;

  virtual void visitASTLimitOffset(const ASTLimitOffset* node, void* data) = 0;

  virtual void visitASTHavingModifier(const ASTHavingModifier* node, void* data) = 0;

  virtual void visitASTAndExpr(const ASTAndExpr* node, void* data) = 0;

  virtual void visitASTOrExpr(const ASTOrExpr* node, void* data) = 0;

  virtual void visitASTBinaryExpression(const ASTBinaryExpression* node, void* data) = 0;

  virtual void visitASTBitwiseShiftExpression(const ASTBitwiseShiftExpression* node, void* data) = 0;

  virtual void visitASTInExpression(const ASTInExpression* node, void* data) = 0;

  virtual void visitASTInList(const ASTInList* node, void* data) = 0;

  virtual void visitASTBetweenExpression(const ASTBetweenExpression* node, void* data) = 0;

  virtual void visitASTUnaryExpression(const ASTUnaryExpression* node, void* data) = 0;

  virtual void visitASTCastExpression(const ASTCastExpression* node, void* data) = 0;

  virtual void visitASTCaseValueExpression(const ASTCaseValueExpression* node, void* data) = 0;

  virtual void visitASTCaseNoValueExpression(const ASTCaseNoValueExpression* node, void* data) = 0;

  virtual void visitASTExtractExpression(const ASTExtractExpression* node, void* data) = 0;

  virtual void visitASTPathExpression(const ASTPathExpression* node, void* data) = 0;

  virtual void visitASTParameterExpr(const ASTParameterExpr* node, void* data) = 0;

  virtual void visitASTIntervalExpr(const ASTIntervalExpr* node, void* data) = 0;

  virtual void visitASTDotIdentifier(const ASTDotIdentifier* node, void* data) = 0;

  virtual void visitASTDotGeneralizedField(const ASTDotGeneralizedField* node, void* data) = 0;

  virtual void visitASTFunctionCall(const ASTFunctionCall* node, void* data) = 0;

  virtual void visitASTNamedArgument(const ASTNamedArgument* node, void* data) = 0;

  virtual void visitASTAnalyticFunctionCall(const ASTAnalyticFunctionCall* node, void* data) = 0;

  virtual void visitASTPartitionBy(const ASTPartitionBy* node, void* data) = 0;

  virtual void visitASTClusterBy(const ASTClusterBy* node, void* data) = 0;

  virtual void visitASTWindowFrameExpr(const ASTWindowFrameExpr* node, void* data) = 0;

  virtual void visitASTWindowFrame(const ASTWindowFrame* node, void* data) = 0;

  virtual void visitASTWindowSpecification(const ASTWindowSpecification* node, void* data) = 0;

  virtual void visitASTWindowDefinition(const ASTWindowDefinition* node, void* data) = 0;

  virtual void visitASTArrayElement(const ASTArrayElement* node, void* data) = 0;

  virtual void visitASTExpressionSubquery(const ASTExpressionSubquery* node, void* data) = 0;

  virtual void visitASTStar(const ASTStar* node, void* data) = 0;

  virtual void visitASTStarReplaceItem(const ASTStarReplaceItem* node, void* data) = 0;

  virtual void visitASTStarExceptList(const ASTStarExceptList* node, void* data) = 0;

  virtual void visitASTStarModifiers(const ASTStarModifiers* node, void* data) = 0;

  virtual void visitASTStarWithModifiers(const ASTStarWithModifiers* node, void* data) = 0;

  virtual void visitASTDotStar(const ASTDotStar* node, void* data) = 0;

  virtual void visitASTDotStarWithModifiers(const ASTDotStarWithModifiers* node, void* data) = 0;

  virtual void visitASTIdentifier(const ASTIdentifier* node, void* data) = 0;

  virtual void visitASTNewConstructorArg(const ASTNewConstructorArg* node, void* data) = 0;

  virtual void visitASTNewConstructor(const ASTNewConstructor* node, void* data) = 0;

  virtual void visitASTArrayConstructor(const ASTArrayConstructor* node, void* data) = 0;

  virtual void visitASTStructConstructorArg(const ASTStructConstructorArg* node, void* data) = 0;

  virtual void visitASTStructConstructorWithParens(const ASTStructConstructorWithParens* node, void* data) = 0;

  virtual void visitASTStructConstructorWithKeyword(const ASTStructConstructorWithKeyword* node, void* data) = 0;

  virtual void visitASTIntLiteral(const ASTIntLiteral* node, void* data) = 0;

  virtual void visitASTNumericLiteral(const ASTNumericLiteral* node, void* data) = 0;

  virtual void visitASTStringLiteral(const ASTStringLiteral* node, void* data) = 0;

  virtual void visitASTBytesLiteral(const ASTBytesLiteral* node, void* data) = 0;

  virtual void visitASTBooleanLiteral(const ASTBooleanLiteral* node, void* data) = 0;

  virtual void visitASTFloatLiteral(const ASTFloatLiteral* node, void* data) = 0;

  virtual void visitASTNullLiteral(const ASTNullLiteral* node, void* data) = 0;

  virtual void visitASTDateOrTimeLiteral(const ASTDateOrTimeLiteral* node, void* data) = 0;

  virtual void visitASTHint(const ASTHint* node, void* data) = 0;

  virtual void visitASTHintEntry(const ASTHintEntry* node, void* data) = 0;

  virtual void visitASTOptionsList(const ASTOptionsList* node, void* data) = 0;

  virtual void visitASTOptionsEntry(const ASTOptionsEntry* node, void* data) = 0;

  virtual void visitASTFunctionParameter(const ASTFunctionParameter* node, void* data) = 0;

  virtual void visitASTFunctionParameters(const ASTFunctionParameters* node, void* data) = 0;

  virtual void visitASTFunctionDeclaration(const ASTFunctionDeclaration* node, void* data) = 0;

  virtual void visitASTSqlFunctionBody(const ASTSqlFunctionBody* node, void* data) = 0;

  virtual void visitASTTVF(const ASTTVF* node, void* data) = 0;

  virtual void visitASTTableClause(const ASTTableClause* node, void* data) = 0;

  virtual void visitASTModelClause(const ASTModelClause* node, void* data) = 0;

  virtual void visitASTTVFArgument(const ASTTVFArgument* node, void* data) = 0;

  virtual void visitASTCreateConstantStatement(const ASTCreateConstantStatement* node, void* data) = 0;

  virtual void visitASTCreateDatabaseStatement(const ASTCreateDatabaseStatement* node, void* data) = 0;

  virtual void visitASTCreateFunctionStatement(const ASTCreateFunctionStatement* node, void* data) = 0;

  virtual void visitASTCreateProcedureStatement(const ASTCreateProcedureStatement* node, void* data) = 0;

  virtual void visitASTCreateTableFunctionStatement(const ASTCreateTableFunctionStatement* node, void* data) = 0;

  virtual void visitASTCreateTableStatement(const ASTCreateTableStatement* node, void* data) = 0;

  virtual void visitASTTransformClause(const ASTTransformClause* node, void* data) = 0;

  virtual void visitASTCreateModelStatement(const ASTCreateModelStatement* node, void* data) = 0;

  virtual void visitASTIndexItemList(const ASTIndexItemList* node, void* data) = 0;

  virtual void visitASTIndexStoringExpressionList(const ASTIndexStoringExpressionList* node, void* data) = 0;

  virtual void visitASTIndexUnnestExpressionList(const ASTIndexUnnestExpressionList* node, void* data) = 0;

  virtual void visitASTCreateIndexStatement(const ASTCreateIndexStatement* node, void* data) = 0;

  virtual void visitASTCreateRowPolicyStatement(const ASTCreateRowPolicyStatement* node, void* data) = 0;

  virtual void visitASTCreateViewStatement(const ASTCreateViewStatement* node, void* data) = 0;

  virtual void visitASTCreateMaterializedViewStatement(const ASTCreateMaterializedViewStatement* node, void* data) = 0;

  virtual void visitASTExportDataStatement(const ASTExportDataStatement* node, void* data) = 0;

  virtual void visitASTCallStatement(const ASTCallStatement* node, void* data) = 0;

  virtual void visitASTDefineTableStatement(const ASTDefineTableStatement* node, void* data) = 0;

  virtual void visitASTCreateExternalTableStatement(const ASTCreateExternalTableStatement* node, void* data) = 0;

  virtual void visitASTSimpleType(const ASTSimpleType* node, void* data) = 0;

  virtual void visitASTArrayType(const ASTArrayType* node, void* data) = 0;

  virtual void visitASTStructType(const ASTStructType* node, void* data) = 0;

  virtual void visitASTStructField(const ASTStructField* node, void* data) = 0;

  virtual void visitASTTemplatedParameterType(const ASTTemplatedParameterType* node, void* data) = 0;

  virtual void visitASTTVFSchema(const ASTTVFSchema* node, void* data) = 0;

  virtual void visitASTTVFSchemaColumn(const ASTTVFSchemaColumn* node, void* data) = 0;

  virtual void visitASTDefaultLiteral(const ASTDefaultLiteral* node, void* data) = 0;

  virtual void visitASTAssertStatement(const ASTAssertStatement* node, void* data) = 0;

  virtual void visitASTAssertRowsModified(const ASTAssertRowsModified* node, void* data) = 0;

  virtual void visitASTDeleteStatement(const ASTDeleteStatement* node, void* data) = 0;

  virtual void visitASTNotNullColumnAttribute(const ASTNotNullColumnAttribute* node, void* data) = 0;

  virtual void visitASTHiddenColumnAttribute(const ASTHiddenColumnAttribute* node, void* data) = 0;

  virtual void visitASTPrimaryKeyColumnAttribute(const ASTPrimaryKeyColumnAttribute* node, void* data) = 0;

  virtual void visitASTForeignKeyColumnAttribute(const ASTForeignKeyColumnAttribute* node, void* data) = 0;

  virtual void visitASTColumnAttributeList(const ASTColumnAttributeList* node, void* data) = 0;

  virtual void visitASTSimpleColumnSchema(const ASTSimpleColumnSchema* node, void* data) = 0;

  virtual void visitASTArrayColumnSchema(const ASTArrayColumnSchema* node, void* data) = 0;

  virtual void visitASTStructColumnSchema(const ASTStructColumnSchema* node, void* data) = 0;

  virtual void visitASTInferredTypeColumnSchema(const ASTInferredTypeColumnSchema* node, void* data) = 0;

  virtual void visitASTStructColumnField(const ASTStructColumnField* node, void* data) = 0;

  virtual void visitASTGeneratedColumnInfo(const ASTGeneratedColumnInfo* node, void* data) = 0;

  virtual void visitASTColumnDefinition(const ASTColumnDefinition* node, void* data) = 0;

  virtual void visitASTPrimaryKey(const ASTPrimaryKey* node, void* data) = 0;

  virtual void visitASTForeignKey(const ASTForeignKey* node, void* data) = 0;

  virtual void visitASTCheckConstraint(const ASTCheckConstraint* node, void* data) = 0;

  virtual void visitASTTableElementList(const ASTTableElementList* node, void* data) = 0;

  virtual void visitASTColumnList(const ASTColumnList* node, void* data) = 0;

  virtual void visitASTColumnPosition(const ASTColumnPosition* node, void* data) = 0;

  virtual void visitASTInsertValuesRow(const ASTInsertValuesRow* node, void* data) = 0;

  virtual void visitASTInsertValuesRowList(const ASTInsertValuesRowList* node, void* data) = 0;

  virtual void visitASTInsertStatement(const ASTInsertStatement* node, void* data) = 0;

  virtual void visitASTUpdateSetValue(const ASTUpdateSetValue* node, void* data) = 0;

  virtual void visitASTUpdateItem(const ASTUpdateItem* node, void* data) = 0;

  virtual void visitASTUpdateItemList(const ASTUpdateItemList* node, void* data) = 0;

  virtual void visitASTUpdateStatement(const ASTUpdateStatement* node, void* data) = 0;

  virtual void visitASTMergeAction(const ASTMergeAction* node, void* data) = 0;

  virtual void visitASTMergeWhenClause(const ASTMergeWhenClause* node, void* data) = 0;

  virtual void visitASTMergeWhenClauseList(const ASTMergeWhenClauseList* node, void* data) = 0;

  virtual void visitASTMergeStatement(const ASTMergeStatement* node, void* data) = 0;

  virtual void visitASTPrivilege(const ASTPrivilege* node, void* data) = 0;

  virtual void visitASTPrivileges(const ASTPrivileges* node, void* data) = 0;

  virtual void visitASTGranteeList(const ASTGranteeList* node, void* data) = 0;

  virtual void visitASTGrantStatement(const ASTGrantStatement* node, void* data) = 0;

  virtual void visitASTRevokeStatement(const ASTRevokeStatement* node, void* data) = 0;

  virtual void visitASTRepeatableClause(const ASTRepeatableClause* node, void* data) = 0;

  virtual void visitASTReplaceFieldsArg(const ASTReplaceFieldsArg* node, void* data) = 0;

  virtual void visitASTReplaceFieldsExpression(const ASTReplaceFieldsExpression* node, void* data) = 0;

  virtual void visitASTSampleSize(const ASTSampleSize* node, void* data) = 0;

  virtual void visitASTWithWeight(const ASTWithWeight* node, void* data) = 0;

  virtual void visitASTSampleSuffix(const ASTSampleSuffix* node, void* data) = 0;

  virtual void visitASTSampleClause(const ASTSampleClause* node, void* data) = 0;

  virtual void visitASTAlterRowPolicyStatement(const ASTAlterRowPolicyStatement* node, void* data) = 0;

  virtual void visitASTSetOptionsAction(const ASTSetOptionsAction* node, void* data) = 0;

  virtual void visitASTAddConstraintAction(const ASTAddConstraintAction* node, void* data) = 0;

  virtual void visitASTDropConstraintAction(const ASTDropConstraintAction* node, void* data) = 0;

  virtual void visitASTAlterConstraintEnforcementAction(const ASTAlterConstraintEnforcementAction* node, void* data) = 0;

  virtual void visitASTAlterConstraintSetOptionsAction(const ASTAlterConstraintSetOptionsAction* node, void* data) = 0;

  virtual void visitASTAddColumnAction(const ASTAddColumnAction* node, void* data) = 0;

  virtual void visitASTDropColumnAction(const ASTDropColumnAction* node, void* data) = 0;

  virtual void visitASTAlterActionList(const ASTAlterActionList* node, void* data) = 0;

  virtual void visitASTAlterTableStatement(const ASTAlterTableStatement* node, void* data) = 0;

  virtual void visitASTAlterViewStatement(const ASTAlterViewStatement* node, void* data) = 0;

  virtual void visitASTAlterMaterializedViewStatement(const ASTAlterMaterializedViewStatement* node, void* data) = 0;

  virtual void visitASTForeignKeyActions(const ASTForeignKeyActions* node, void* data) = 0;

  virtual void visitASTForeignKeyReference(const ASTForeignKeyReference* node, void* data) = 0;

  virtual void visitASTStatementList(const ASTStatementList* node, void* data) = 0;

  virtual void visitASTScript(const ASTScript* node, void* data) = 0;

  virtual void visitASTIfStatement(const ASTIfStatement* node, void* data) = 0;

  virtual void visitASTBeginEndBlock(const ASTBeginEndBlock* node, void* data) = 0;

  virtual void visitASTIdentifierList(const ASTIdentifierList* node, void* data) = 0;

  virtual void visitASTVariableDeclaration(const ASTVariableDeclaration* node, void* data) = 0;

  virtual void visitASTWhileStatement(const ASTWhileStatement* node, void* data) = 0;

  virtual void visitASTBreakStatement(const ASTBreakStatement* node, void* data) = 0;

  virtual void visitASTContinueStatement(const ASTContinueStatement* node, void* data) = 0;

  virtual void visitASTSingleAssignment(const ASTSingleAssignment* node, void* data) = 0;

  virtual void visitASTAssignmentFromStruct(const ASTAssignmentFromStruct* node, void* data) = 0;

};

class DefaultParseTreeVisitor : public ParseTreeVisitor {
 public:
  virtual void defaultVisit(const ASTNode* node, void* data) = 0;
  void visit(const ASTNode* node, void* data) override {
    defaultVisit(node, data);
  }
  void visitASTHintedStatement(const ASTHintedStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTExplainStatement(const ASTExplainStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDescribeStatement(const ASTDescribeStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTShowStatement(const ASTShowStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTransactionIsolationLevel(const ASTTransactionIsolationLevel* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTransactionReadWriteMode(const ASTTransactionReadWriteMode* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTransactionModeList(const ASTTransactionModeList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBeginStatement(const ASTBeginStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSetTransactionStatement(const ASTSetTransactionStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCommitStatement(const ASTCommitStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRollbackStatement(const ASTRollbackStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStartBatchStatement(const ASTStartBatchStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRunBatchStatement(const ASTRunBatchStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAbortBatchStatement(const ASTAbortBatchStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropStatement(const ASTDropStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropFunctionStatement(const ASTDropFunctionStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropRowPolicyStatement(const ASTDropRowPolicyStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropAllRowPoliciesStatement(const ASTDropAllRowPoliciesStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropMaterializedViewStatement(const ASTDropMaterializedViewStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRenameStatement(const ASTRenameStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTImportStatement(const ASTImportStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTModuleStatement(const ASTModuleStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTQueryStatement(const ASTQueryStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWithClause(const ASTWithClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWithClauseEntry(const ASTWithClauseEntry* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTQuery(const ASTQuery* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSetOperation(const ASTSetOperation* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSelect(const ASTSelect* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSelectAs(const ASTSelectAs* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSelectList(const ASTSelectList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSelectColumn(const ASTSelectColumn* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlias(const ASTAlias* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIntoAlias(const ASTIntoAlias* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFromClause(const ASTFromClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWindowClause(const ASTWindowClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUnnestExpression(const ASTUnnestExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWithOffset(const ASTWithOffset* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUnnestExpressionWithOptAliasAndOffset(const ASTUnnestExpressionWithOptAliasAndOffset* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTablePathExpression(const ASTTablePathExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTableSubquery(const ASTTableSubquery* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTJoin(const ASTJoin* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTParenthesizedJoin(const ASTParenthesizedJoin* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOnClause(const ASTOnClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUsingClause(const ASTUsingClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWhereClause(const ASTWhereClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRollup(const ASTRollup* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTForSystemTime(const ASTForSystemTime* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTGroupingItem(const ASTGroupingItem* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTGroupBy(const ASTGroupBy* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTHaving(const ASTHaving* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCollate(const ASTCollate* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOrderingExpression(const ASTOrderingExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOrderBy(const ASTOrderBy* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTLimitOffset(const ASTLimitOffset* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTHavingModifier(const ASTHavingModifier* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAndExpr(const ASTAndExpr* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOrExpr(const ASTOrExpr* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBinaryExpression(const ASTBinaryExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBitwiseShiftExpression(const ASTBitwiseShiftExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInExpression(const ASTInExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInList(const ASTInList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBetweenExpression(const ASTBetweenExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUnaryExpression(const ASTUnaryExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCastExpression(const ASTCastExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCaseValueExpression(const ASTCaseValueExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCaseNoValueExpression(const ASTCaseNoValueExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTExtractExpression(const ASTExtractExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPathExpression(const ASTPathExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTParameterExpr(const ASTParameterExpr* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIntervalExpr(const ASTIntervalExpr* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDotIdentifier(const ASTDotIdentifier* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDotGeneralizedField(const ASTDotGeneralizedField* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFunctionCall(const ASTFunctionCall* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNamedArgument(const ASTNamedArgument* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAnalyticFunctionCall(const ASTAnalyticFunctionCall* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPartitionBy(const ASTPartitionBy* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTClusterBy(const ASTClusterBy* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWindowFrameExpr(const ASTWindowFrameExpr* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWindowFrame(const ASTWindowFrame* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWindowSpecification(const ASTWindowSpecification* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWindowDefinition(const ASTWindowDefinition* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTArrayElement(const ASTArrayElement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTExpressionSubquery(const ASTExpressionSubquery* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStar(const ASTStar* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStarReplaceItem(const ASTStarReplaceItem* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStarExceptList(const ASTStarExceptList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStarModifiers(const ASTStarModifiers* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStarWithModifiers(const ASTStarWithModifiers* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDotStar(const ASTDotStar* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDotStarWithModifiers(const ASTDotStarWithModifiers* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIdentifier(const ASTIdentifier* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNewConstructorArg(const ASTNewConstructorArg* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNewConstructor(const ASTNewConstructor* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTArrayConstructor(const ASTArrayConstructor* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructConstructorArg(const ASTStructConstructorArg* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructConstructorWithParens(const ASTStructConstructorWithParens* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructConstructorWithKeyword(const ASTStructConstructorWithKeyword* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIntLiteral(const ASTIntLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNumericLiteral(const ASTNumericLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStringLiteral(const ASTStringLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBytesLiteral(const ASTBytesLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBooleanLiteral(const ASTBooleanLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFloatLiteral(const ASTFloatLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNullLiteral(const ASTNullLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDateOrTimeLiteral(const ASTDateOrTimeLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTHint(const ASTHint* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTHintEntry(const ASTHintEntry* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOptionsList(const ASTOptionsList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTOptionsEntry(const ASTOptionsEntry* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFunctionParameter(const ASTFunctionParameter* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFunctionParameters(const ASTFunctionParameters* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTFunctionDeclaration(const ASTFunctionDeclaration* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSqlFunctionBody(const ASTSqlFunctionBody* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTVF(const ASTTVF* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTableClause(const ASTTableClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTModelClause(const ASTModelClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTVFArgument(const ASTTVFArgument* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateConstantStatement(const ASTCreateConstantStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateDatabaseStatement(const ASTCreateDatabaseStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateFunctionStatement(const ASTCreateFunctionStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateProcedureStatement(const ASTCreateProcedureStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateTableFunctionStatement(const ASTCreateTableFunctionStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateTableStatement(const ASTCreateTableStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTransformClause(const ASTTransformClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateModelStatement(const ASTCreateModelStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIndexItemList(const ASTIndexItemList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIndexStoringExpressionList(const ASTIndexStoringExpressionList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIndexUnnestExpressionList(const ASTIndexUnnestExpressionList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateIndexStatement(const ASTCreateIndexStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateRowPolicyStatement(const ASTCreateRowPolicyStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateViewStatement(const ASTCreateViewStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateMaterializedViewStatement(const ASTCreateMaterializedViewStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTExportDataStatement(const ASTExportDataStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCallStatement(const ASTCallStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDefineTableStatement(const ASTDefineTableStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCreateExternalTableStatement(const ASTCreateExternalTableStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSimpleType(const ASTSimpleType* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTArrayType(const ASTArrayType* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructType(const ASTStructType* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructField(const ASTStructField* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTemplatedParameterType(const ASTTemplatedParameterType* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTVFSchema(const ASTTVFSchema* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTVFSchemaColumn(const ASTTVFSchemaColumn* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDefaultLiteral(const ASTDefaultLiteral* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAssertStatement(const ASTAssertStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAssertRowsModified(const ASTAssertRowsModified* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDeleteStatement(const ASTDeleteStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTNotNullColumnAttribute(const ASTNotNullColumnAttribute* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTHiddenColumnAttribute(const ASTHiddenColumnAttribute* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPrimaryKeyColumnAttribute(const ASTPrimaryKeyColumnAttribute* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTForeignKeyColumnAttribute(const ASTForeignKeyColumnAttribute* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTColumnAttributeList(const ASTColumnAttributeList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSimpleColumnSchema(const ASTSimpleColumnSchema* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTArrayColumnSchema(const ASTArrayColumnSchema* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructColumnSchema(const ASTStructColumnSchema* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInferredTypeColumnSchema(const ASTInferredTypeColumnSchema* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStructColumnField(const ASTStructColumnField* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTGeneratedColumnInfo(const ASTGeneratedColumnInfo* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTColumnDefinition(const ASTColumnDefinition* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPrimaryKey(const ASTPrimaryKey* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTForeignKey(const ASTForeignKey* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTCheckConstraint(const ASTCheckConstraint* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTTableElementList(const ASTTableElementList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTColumnList(const ASTColumnList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTColumnPosition(const ASTColumnPosition* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInsertValuesRow(const ASTInsertValuesRow* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInsertValuesRowList(const ASTInsertValuesRowList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTInsertStatement(const ASTInsertStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUpdateSetValue(const ASTUpdateSetValue* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUpdateItem(const ASTUpdateItem* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUpdateItemList(const ASTUpdateItemList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTUpdateStatement(const ASTUpdateStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTMergeAction(const ASTMergeAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTMergeWhenClause(const ASTMergeWhenClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTMergeWhenClauseList(const ASTMergeWhenClauseList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTMergeStatement(const ASTMergeStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPrivilege(const ASTPrivilege* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTPrivileges(const ASTPrivileges* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTGranteeList(const ASTGranteeList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTGrantStatement(const ASTGrantStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRevokeStatement(const ASTRevokeStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTRepeatableClause(const ASTRepeatableClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTReplaceFieldsArg(const ASTReplaceFieldsArg* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTReplaceFieldsExpression(const ASTReplaceFieldsExpression* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSampleSize(const ASTSampleSize* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWithWeight(const ASTWithWeight* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSampleSuffix(const ASTSampleSuffix* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSampleClause(const ASTSampleClause* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterRowPolicyStatement(const ASTAlterRowPolicyStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSetOptionsAction(const ASTSetOptionsAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAddConstraintAction(const ASTAddConstraintAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropConstraintAction(const ASTDropConstraintAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterConstraintEnforcementAction(const ASTAlterConstraintEnforcementAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterConstraintSetOptionsAction(const ASTAlterConstraintSetOptionsAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAddColumnAction(const ASTAddColumnAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTDropColumnAction(const ASTDropColumnAction* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterActionList(const ASTAlterActionList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterTableStatement(const ASTAlterTableStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterViewStatement(const ASTAlterViewStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAlterMaterializedViewStatement(const ASTAlterMaterializedViewStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTForeignKeyActions(const ASTForeignKeyActions* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTForeignKeyReference(const ASTForeignKeyReference* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTStatementList(const ASTStatementList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTScript(const ASTScript* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIfStatement(const ASTIfStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBeginEndBlock(const ASTBeginEndBlock* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTIdentifierList(const ASTIdentifierList* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTVariableDeclaration(const ASTVariableDeclaration* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTWhileStatement(const ASTWhileStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTBreakStatement(const ASTBreakStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTContinueStatement(const ASTContinueStatement* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTSingleAssignment(const ASTSingleAssignment* node, void* data) override {
    defaultVisit(node, data);
  }

  void visitASTAssignmentFromStruct(const ASTAssignmentFromStruct* node, void* data) override {
    defaultVisit(node, data);
  }

};

}  // namespace zetasql
#endif  // STORAGE_ZETASQL_PARSER_PARSE_TREE_VISITOR_H_
