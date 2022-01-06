#include "zetasql/parser/parse_tree.h"
namespace zetasql {
void ASTHintedStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHintedStatement(this, data);
}

void ASTExplainStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTExplainStatement(this, data);
}

void ASTDescribeStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDescribeStatement(this, data);
}

void ASTShowStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTShowStatement(this, data);
}

void ASTTransactionIsolationLevel::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTransactionIsolationLevel(this, data);
}

void ASTTransactionReadWriteMode::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTransactionReadWriteMode(this, data);
}

void ASTTransactionModeList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTransactionModeList(this, data);
}

void ASTBeginStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBeginStatement(this, data);
}

void ASTSetTransactionStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSetTransactionStatement(this, data);
}

void ASTCommitStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCommitStatement(this, data);
}

void ASTRollbackStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRollbackStatement(this, data);
}

void ASTStartBatchStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStartBatchStatement(this, data);
}

void ASTRunBatchStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRunBatchStatement(this, data);
}

void ASTAbortBatchStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAbortBatchStatement(this, data);
}

void ASTDropStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropStatement(this, data);
}

void ASTDropFunctionStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropFunctionStatement(this, data);
}

void ASTDropRowPolicyStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropRowPolicyStatement(this, data);
}

void ASTDropAllRowPoliciesStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropAllRowPoliciesStatement(this, data);
}

void ASTDropMaterializedViewStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropMaterializedViewStatement(this, data);
}

void ASTRenameStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRenameStatement(this, data);
}

void ASTImportStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTImportStatement(this, data);
}

void ASTModuleStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTModuleStatement(this, data);
}

void ASTQueryStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTQueryStatement(this, data);
}

void ASTWithClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWithClause(this, data);
}

void ASTWithClauseEntry::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWithClauseEntry(this, data);
}

void ASTQuery::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTQuery(this, data);
}

void ASTSetOperation::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSetOperation(this, data);
}

void ASTSelect::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSelect(this, data);
}

void ASTSelectAs::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSelectAs(this, data);
}

void ASTSelectList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSelectList(this, data);
}

void ASTSelectColumn::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSelectColumn(this, data);
}

void ASTAlias::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlias(this, data);
}

void ASTIntoAlias::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIntoAlias(this, data);
}

void ASTFromClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFromClause(this, data);
}

void ASTWindowClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWindowClause(this, data);
}

void ASTUnnestExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUnnestExpression(this, data);
}

void ASTWithOffset::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWithOffset(this, data);
}

void ASTUnnestExpressionWithOptAliasAndOffset::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUnnestExpressionWithOptAliasAndOffset(this, data);
}

void ASTTablePathExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTablePathExpression(this, data);
}

void ASTTableSubquery::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTableSubquery(this, data);
}

void ASTJoin::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTJoin(this, data);
}

void ASTParenthesizedJoin::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTParenthesizedJoin(this, data);
}

void ASTOnClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOnClause(this, data);
}

void ASTUsingClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUsingClause(this, data);
}

void ASTWhereClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWhereClause(this, data);
}

void ASTRollup::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRollup(this, data);
}

void ASTForSystemTime::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTForSystemTime(this, data);
}

void ASTGroupingItem::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTGroupingItem(this, data);
}

void ASTGroupBy::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTGroupBy(this, data);
}

void ASTHaving::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHaving(this, data);
}

void ASTCollate::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCollate(this, data);
}

void ASTOrderingExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOrderingExpression(this, data);
}

void ASTOrderBy::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOrderBy(this, data);
}

void ASTLimitOffset::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTLimitOffset(this, data);
}

void ASTHavingModifier::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHavingModifier(this, data);
}

void ASTAndExpr::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAndExpr(this, data);
}

void ASTOrExpr::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOrExpr(this, data);
}

void ASTBinaryExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBinaryExpression(this, data);
}

void ASTBitwiseShiftExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBitwiseShiftExpression(this, data);
}

void ASTInExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInExpression(this, data);
}

void ASTInList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInList(this, data);
}

void ASTBetweenExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBetweenExpression(this, data);
}

void ASTUnaryExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUnaryExpression(this, data);
}

void ASTCastExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCastExpression(this, data);
}

void ASTCaseValueExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCaseValueExpression(this, data);
}

void ASTCaseNoValueExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCaseNoValueExpression(this, data);
}

void ASTExtractExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTExtractExpression(this, data);
}

void ASTPathExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPathExpression(this, data);
}

void ASTParameterExpr::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTParameterExpr(this, data);
}

void ASTIntervalExpr::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIntervalExpr(this, data);
}

void ASTDotIdentifier::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDotIdentifier(this, data);
}

void ASTDotGeneralizedField::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDotGeneralizedField(this, data);
}

void ASTFunctionCall::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFunctionCall(this, data);
}

void ASTNamedArgument::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNamedArgument(this, data);
}

void ASTAnalyticFunctionCall::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAnalyticFunctionCall(this, data);
}

void ASTPartitionBy::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPartitionBy(this, data);
}

void ASTClusterBy::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTClusterBy(this, data);
}

void ASTWindowFrameExpr::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWindowFrameExpr(this, data);
}

void ASTWindowFrame::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWindowFrame(this, data);
}

void ASTWindowSpecification::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWindowSpecification(this, data);
}

void ASTWindowDefinition::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWindowDefinition(this, data);
}

void ASTArrayElement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTArrayElement(this, data);
}

void ASTExpressionSubquery::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTExpressionSubquery(this, data);
}

void ASTStar::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStar(this, data);
}

void ASTStarReplaceItem::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStarReplaceItem(this, data);
}

void ASTStarExceptList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStarExceptList(this, data);
}

void ASTStarModifiers::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStarModifiers(this, data);
}

void ASTStarWithModifiers::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStarWithModifiers(this, data);
}

void ASTDotStar::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDotStar(this, data);
}

void ASTDotStarWithModifiers::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDotStarWithModifiers(this, data);
}

void ASTIdentifier::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIdentifier(this, data);
}

void ASTNewConstructorArg::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNewConstructorArg(this, data);
}

void ASTNewConstructor::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNewConstructor(this, data);
}

void ASTArrayConstructor::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTArrayConstructor(this, data);
}

void ASTStructConstructorArg::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructConstructorArg(this, data);
}

void ASTStructConstructorWithParens::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructConstructorWithParens(this, data);
}

void ASTStructConstructorWithKeyword::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructConstructorWithKeyword(this, data);
}

void ASTIntLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIntLiteral(this, data);
}

void ASTNumericLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNumericLiteral(this, data);
}

void ASTStringLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStringLiteral(this, data);
}

void ASTBytesLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBytesLiteral(this, data);
}

void ASTBooleanLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBooleanLiteral(this, data);
}

void ASTFloatLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFloatLiteral(this, data);
}

void ASTNullLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNullLiteral(this, data);
}

void ASTDateOrTimeLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDateOrTimeLiteral(this, data);
}

void ASTHint::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHint(this, data);
}

void ASTHintEntry::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHintEntry(this, data);
}

void ASTOptionsList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOptionsList(this, data);
}

void ASTOptionsEntry::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTOptionsEntry(this, data);
}

void ASTFunctionParameter::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFunctionParameter(this, data);
}

void ASTFunctionParameters::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFunctionParameters(this, data);
}

void ASTFunctionDeclaration::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTFunctionDeclaration(this, data);
}

void ASTSqlFunctionBody::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSqlFunctionBody(this, data);
}

void ASTTVF::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTVF(this, data);
}

void ASTTableClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTableClause(this, data);
}

void ASTModelClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTModelClause(this, data);
}

void ASTTVFArgument::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTVFArgument(this, data);
}

void ASTCreateConstantStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateConstantStatement(this, data);
}

void ASTCreateDatabaseStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateDatabaseStatement(this, data);
}

void ASTCreateFunctionStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateFunctionStatement(this, data);
}

void ASTCreateProcedureStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateProcedureStatement(this, data);
}

void ASTCreateTableFunctionStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateTableFunctionStatement(this, data);
}

void ASTCreateTableStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateTableStatement(this, data);
}

void ASTTransformClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTransformClause(this, data);
}

void ASTCreateModelStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateModelStatement(this, data);
}

void ASTIndexItemList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIndexItemList(this, data);
}

void ASTIndexStoringExpressionList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIndexStoringExpressionList(this, data);
}

void ASTIndexUnnestExpressionList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIndexUnnestExpressionList(this, data);
}

void ASTCreateIndexStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateIndexStatement(this, data);
}

void ASTCreateRowPolicyStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateRowPolicyStatement(this, data);
}

void ASTCreateViewStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateViewStatement(this, data);
}

void ASTCreateMaterializedViewStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateMaterializedViewStatement(this, data);
}

void ASTExportDataStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTExportDataStatement(this, data);
}

void ASTCallStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCallStatement(this, data);
}

void ASTDefineTableStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDefineTableStatement(this, data);
}

void ASTCreateExternalTableStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCreateExternalTableStatement(this, data);
}

void ASTSimpleType::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSimpleType(this, data);
}

void ASTArrayType::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTArrayType(this, data);
}

void ASTStructType::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructType(this, data);
}

void ASTStructField::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructField(this, data);
}

void ASTTemplatedParameterType::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTemplatedParameterType(this, data);
}

void ASTTVFSchema::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTVFSchema(this, data);
}

void ASTTVFSchemaColumn::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTVFSchemaColumn(this, data);
}

void ASTDefaultLiteral::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDefaultLiteral(this, data);
}

void ASTAssertStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAssertStatement(this, data);
}

void ASTAssertRowsModified::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAssertRowsModified(this, data);
}

void ASTDeleteStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDeleteStatement(this, data);
}

void ASTNotNullColumnAttribute::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTNotNullColumnAttribute(this, data);
}

void ASTHiddenColumnAttribute::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTHiddenColumnAttribute(this, data);
}

void ASTPrimaryKeyColumnAttribute::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPrimaryKeyColumnAttribute(this, data);
}

void ASTForeignKeyColumnAttribute::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTForeignKeyColumnAttribute(this, data);
}

void ASTColumnAttributeList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTColumnAttributeList(this, data);
}

void ASTSimpleColumnSchema::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSimpleColumnSchema(this, data);
}

void ASTArrayColumnSchema::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTArrayColumnSchema(this, data);
}

void ASTStructColumnSchema::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructColumnSchema(this, data);
}

void ASTInferredTypeColumnSchema::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInferredTypeColumnSchema(this, data);
}

void ASTStructColumnField::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStructColumnField(this, data);
}

void ASTGeneratedColumnInfo::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTGeneratedColumnInfo(this, data);
}

void ASTColumnDefinition::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTColumnDefinition(this, data);
}

void ASTPrimaryKey::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPrimaryKey(this, data);
}

void ASTForeignKey::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTForeignKey(this, data);
}

void ASTCheckConstraint::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTCheckConstraint(this, data);
}

void ASTTableElementList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTTableElementList(this, data);
}

void ASTColumnList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTColumnList(this, data);
}

void ASTColumnPosition::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTColumnPosition(this, data);
}

void ASTInsertValuesRow::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInsertValuesRow(this, data);
}

void ASTInsertValuesRowList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInsertValuesRowList(this, data);
}

void ASTInsertStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTInsertStatement(this, data);
}

void ASTUpdateSetValue::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUpdateSetValue(this, data);
}

void ASTUpdateItem::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUpdateItem(this, data);
}

void ASTUpdateItemList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUpdateItemList(this, data);
}

void ASTUpdateStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTUpdateStatement(this, data);
}

void ASTMergeAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTMergeAction(this, data);
}

void ASTMergeWhenClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTMergeWhenClause(this, data);
}

void ASTMergeWhenClauseList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTMergeWhenClauseList(this, data);
}

void ASTMergeStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTMergeStatement(this, data);
}

void ASTPrivilege::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPrivilege(this, data);
}

void ASTPrivileges::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTPrivileges(this, data);
}

void ASTGranteeList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTGranteeList(this, data);
}

void ASTGrantStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTGrantStatement(this, data);
}

void ASTRevokeStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRevokeStatement(this, data);
}

void ASTRepeatableClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTRepeatableClause(this, data);
}

void ASTReplaceFieldsArg::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTReplaceFieldsArg(this, data);
}

void ASTReplaceFieldsExpression::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTReplaceFieldsExpression(this, data);
}

void ASTSampleSize::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSampleSize(this, data);
}

void ASTWithWeight::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWithWeight(this, data);
}

void ASTSampleSuffix::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSampleSuffix(this, data);
}

void ASTSampleClause::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSampleClause(this, data);
}

void ASTAlterRowPolicyStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterRowPolicyStatement(this, data);
}

void ASTSetOptionsAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSetOptionsAction(this, data);
}

void ASTAddConstraintAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAddConstraintAction(this, data);
}

void ASTDropConstraintAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropConstraintAction(this, data);
}

void ASTAlterConstraintEnforcementAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterConstraintEnforcementAction(this, data);
}

void ASTAlterConstraintSetOptionsAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterConstraintSetOptionsAction(this, data);
}

void ASTAddColumnAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAddColumnAction(this, data);
}

void ASTDropColumnAction::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTDropColumnAction(this, data);
}

void ASTAlterActionList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterActionList(this, data);
}

void ASTAlterTableStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterTableStatement(this, data);
}

void ASTAlterViewStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterViewStatement(this, data);
}

void ASTAlterMaterializedViewStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAlterMaterializedViewStatement(this, data);
}

void ASTForeignKeyActions::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTForeignKeyActions(this, data);
}

void ASTForeignKeyReference::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTForeignKeyReference(this, data);
}

void ASTStatementList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTStatementList(this, data);
}

void ASTScript::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTScript(this, data);
}

void ASTIfStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIfStatement(this, data);
}

void ASTBeginEndBlock::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBeginEndBlock(this, data);
}

void ASTIdentifierList::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTIdentifierList(this, data);
}

void ASTVariableDeclaration::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTVariableDeclaration(this, data);
}

void ASTWhileStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTWhileStatement(this, data);
}

void ASTBreakStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTBreakStatement(this, data);
}

void ASTContinueStatement::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTContinueStatement(this, data);
}

void ASTSingleAssignment::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTSingleAssignment(this, data);
}

void ASTAssignmentFromStruct::Accept(ParseTreeVisitor* visitor, void* data) const {
  visitor->visitASTAssignmentFromStruct(this, data);
}

}  // namespace zetasql
