use rnmdb_catalog::{
    IndexMethod, MAX_WASM_FUNCTION_MODULE_BYTES, Privilege, TriggerEvent, TriggerTiming,
};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::SqlType;

use crate::{
    ast::{
        Assignment, CaseWhen, ColumnDef, ColumnReference, CreateFunctionImplementation,
        ExplainFormat, Expr, GeneratedColumn, Ident, IndexKeyDef, JoinClause, JoinKind,
        LateralJoin, ObjectName, OrderByExpr, RangeLiteralBounds, SelectItem, SelectSubquery,
        SortDirection, Statement, TransactionAction, WasmFunctionBody,
    },
    lexer::{Token, TokenKind, lex},
};

mod grouping;

use grouping::{cube_grouping_sets, grouping_sets_union, rollup_grouping_sets};

pub fn parse_statement(input: &str) -> Result<Statement> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let statement = parser.parse_statement()?;
    parser.consume_optional_semicolon();
    parser.expect_end()?;
    Ok(statement)
}

pub fn parse_expr(input: &str) -> Result<Expr> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    parser.expect_end()?;
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

#[derive(Default)]
struct WasmFunctionOptions {
    max_memory_bytes: Option<u64>,
    max_instructions: Option<u64>,
    timeout_millis: Option<u64>,
}

impl WasmFunctionOptions {
    fn set(&mut self, name: &str, value: u64) -> Result<()> {
        let slot = match name {
            "max_memory_bytes" => &mut self.max_memory_bytes,
            "max_instructions" => &mut self.max_instructions,
            "timeout_ms" => &mut self.timeout_millis,
            unknown => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("unknown wasm function option {unknown}"),
                ));
            }
        };
        if slot.replace(value).is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate wasm function option {name}"),
            ));
        }
        Ok(())
    }

    fn into_body(self, module_bytes: Vec<u8>) -> Result<WasmFunctionBody> {
        Ok(WasmFunctionBody {
            module_bytes,
            max_memory_bytes: required_wasm_option(self.max_memory_bytes, "max_memory_bytes")?,
            max_instructions: required_wasm_option(self.max_instructions, "max_instructions")?,
            timeout_millis: required_wasm_option(self.timeout_millis, "timeout_ms")?,
        })
    }
}

#[derive(Default)]
struct QueryTail {
    order_by: Vec<OrderByExpr>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl QueryTail {
    fn is_empty(&self) -> bool {
        self.order_by.is_empty() && self.limit.is_none() && self.offset.is_none()
    }
}

#[derive(Clone, Copy)]
struct ExplainOptions {
    analyze: bool,
    format: ExplainFormat,
}

impl Default for ExplainOptions {
    fn default() -> Self {
        Self {
            analyze: false,
            format: ExplainFormat::Logical,
        }
    }
}

impl ExplainOptions {
    fn enable_analyze(&mut self) -> std::result::Result<(), &'static str> {
        if self.analyze {
            return Err("duplicate EXPLAIN ANALYZE option");
        }
        self.analyze = true;
        Ok(())
    }

    fn set_format(&mut self, format: ExplainFormat) -> std::result::Result<(), &'static str> {
        if self.format != ExplainFormat::Logical {
            return Err("conflicting EXPLAIN format options");
        }
        self.format = format;
        Ok(())
    }
}

#[derive(Default)]
struct CreateTableElements {
    columns: Vec<ColumnDef>,
    foreign_keys: Vec<(Ident, ColumnReference)>,
}

struct CreateOperatorSignature {
    symbol: String,
    left_type: SqlType,
    right_type: SqlType,
    result_type: SqlType,
    function: Ident,
}

#[derive(Default)]
struct CreateOperatorOptions {
    precedence: Option<u8>,
    commutator: Option<String>,
    negator: Option<String>,
    selectivity: Option<Ident>,
}

struct ColumnOptions {
    nullable: bool,
    encrypted: bool,
    generated: Option<GeneratedColumn>,
    references: Option<ColumnReference>,
}

impl Default for ColumnOptions {
    fn default() -> Self {
        Self {
            nullable: true,
            encrypted: false,
            generated: None,
            references: None,
        }
    }
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        match self.peek_kind() {
            Some(TokenKind::Create) => self.parse_create(),
            Some(TokenKind::Alter) => self.parse_alter(),
            Some(TokenKind::Drop) => self.parse_drop(),
            Some(TokenKind::Grant) => self.parse_grant(),
            Some(TokenKind::Call) => self.parse_call_procedure(),
            Some(TokenKind::Insert) => self.parse_insert(),
            Some(TokenKind::Update) => self.parse_update(),
            Some(TokenKind::Delete) => self.parse_delete(),
            Some(TokenKind::Select) => self.parse_query(),
            Some(TokenKind::With) => self.parse_recursive_cte(),
            Some(TokenKind::Begin) => self.parse_transaction(TransactionAction::Begin),
            Some(TokenKind::Commit) => self.parse_transaction(TransactionAction::Commit),
            Some(TokenKind::Rollback) => self.parse_transaction(TransactionAction::Rollback),
            Some(TokenKind::Explain) => self.parse_explain(),
            Some(kind) => Err(self.error(format!("unexpected statement token {kind:?}"))),
            None => Err(self.error("empty statement")),
        }
    }

    fn parse_explain(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Explain)?;
        let options = self.parse_explain_options()?;
        self.reject_nested_explain()?;
        Ok(Statement::Explain {
            analyze: options.analyze,
            format: options.format,
            statement: Box::new(self.parse_statement()?),
        })
    }

    fn parse_explain_options(&mut self) -> Result<ExplainOptions> {
        let mut options = ExplainOptions::default();
        while self.parse_explain_option(&mut options)? {}
        Ok(options)
    }

    fn parse_explain_option(&mut self, options: &mut ExplainOptions) -> Result<bool> {
        if self.consume_if(&TokenKind::Analyze) {
            return options
                .enable_analyze()
                .map(|()| true)
                .map_err(|message| self.error(message));
        }
        if self.consume_identifier_keyword("costs") {
            return options
                .set_format(ExplainFormat::Costs)
                .map(|()| true)
                .map_err(|message| self.error(message));
        }
        if self.consume_identifier_keyword("physical") {
            return options
                .set_format(ExplainFormat::Physical)
                .map(|()| true)
                .map_err(|message| self.error(message));
        }
        Ok(false)
    }

    fn reject_nested_explain(&self) -> Result<()> {
        if matches!(self.peek_kind(), Some(TokenKind::Explain)) {
            return Err(self.error("nested EXPLAIN is not supported"));
        }
        Ok(())
    }

    fn parse_create(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Create)?;
        let unique = self.consume_if(&TokenKind::Unique);
        match self.peek_kind() {
            Some(TokenKind::Index) => self.parse_create_index_tail(unique),
            Some(TokenKind::Table) => self.parse_create_table_tail(),
            Some(TokenKind::Trigger) => self.parse_create_trigger_tail(unique),
            Some(TokenKind::Function) => self.parse_create_function_tail(),
            Some(TokenKind::Procedure) => self.parse_create_procedure_tail(),
            Some(TokenKind::OperatorKeyword) => self.parse_create_operator_tail(),
            Some(TokenKind::Role) => self.parse_create_role_tail(),
            Some(TokenKind::Policy) => self.parse_create_policy_tail(),
            Some(kind) if unique => {
                Err(self.error(format!("unexpected CREATE UNIQUE target {kind:?}")))
            }
            Some(kind) => Err(self.error(format!("unexpected CREATE target {kind:?}"))),
            None => Err(self.error("expected CREATE target")),
        }
    }

    fn parse_create_table_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Table)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let name = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let mut elements = self.parse_create_table_elements()?;
        self.expect_keyword(TokenKind::RightParen)?;
        self.apply_table_foreign_keys(&mut elements.columns, elements.foreign_keys)?;

        Ok(Statement::CreateTable {
            name,
            columns: elements.columns,
            if_not_exists,
        })
    }

    fn parse_create_table_elements(&mut self) -> Result<CreateTableElements> {
        let mut elements = CreateTableElements::default();
        loop {
            if self.next_is_identifier_keyword("foreign") {
                elements.foreign_keys.push(self.parse_table_foreign_key()?);
            } else {
                elements.columns.push(self.parse_column_def()?);
            }

            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(elements)
    }

    fn parse_create_index_tail(&mut self, unique: bool) -> Result<Statement> {
        self.expect_keyword(TokenKind::Index)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let (name, table, method, keys) = self.parse_create_index_definition()?;

        Ok(Statement::CreateIndex {
            name,
            table,
            keys,
            method,
            unique,
            if_not_exists,
        })
    }

    fn parse_create_index_definition(
        &mut self,
    ) -> Result<(ObjectName, ObjectName, IndexMethod, Vec<IndexKeyDef>)> {
        let name = self.parse_object_name()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        let method = self.parse_optional_index_method()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let keys = self.parse_index_keys()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok((name, table, method, keys))
    }

    fn parse_create_trigger_tail(&mut self, unique: bool) -> Result<Statement> {
        if unique {
            return Err(self.error("CREATE UNIQUE TRIGGER is not supported"));
        }
        self.expect_keyword(TokenKind::Trigger)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let (name, event, table) = self.parse_create_trigger_header()?;
        let body = self.parse_trigger_sql_body()?;
        Ok(Statement::CreateTrigger {
            name,
            table,
            timing: TriggerTiming::After,
            event,
            body,
            if_not_exists,
        })
    }

    fn parse_create_trigger_header(&mut self) -> Result<(Ident, TriggerEvent, ObjectName)> {
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::After)?;
        let event = self.parse_trigger_event()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        Ok((name, event, table))
    }

    fn parse_trigger_sql_body(&mut self) -> Result<String> {
        self.expect_keyword(TokenKind::Execute)?;
        if !self.consume_identifier_keyword("sql") {
            return Err(self.error("expected SQL after EXECUTE"));
        }
        self.parse_string_literal("trigger SQL body")
    }

    fn parse_trigger_event(&mut self) -> Result<TriggerEvent> {
        match self.peek_kind() {
            Some(TokenKind::Insert) => {
                self.bump();
                Ok(TriggerEvent::Insert)
            }
            Some(TokenKind::Update) => {
                self.bump();
                Ok(TriggerEvent::Update)
            }
            Some(TokenKind::Delete) => {
                self.bump();
                Ok(TriggerEvent::Delete)
            }
            Some(kind) => Err(self.error(format!("unexpected trigger event {kind:?}"))),
            None => Err(self.error("expected trigger event")),
        }
    }

    fn parse_index_keys(&mut self) -> Result<Vec<IndexKeyDef>> {
        let mut keys = Vec::new();
        loop {
            if self.consume_if(&TokenKind::LeftParen) {
                let expr = self.parse_expr()?;
                self.expect_keyword(TokenKind::RightParen)?;
                keys.push(IndexKeyDef::Expression(expr));
            } else {
                keys.push(IndexKeyDef::Column(self.parse_ident()?));
            }
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(keys)
    }

    fn parse_optional_index_method(&mut self) -> Result<IndexMethod> {
        if !self.consume_if(&TokenKind::Using) {
            return Ok(IndexMethod::BTree);
        }
        let method = self.parse_ident()?;
        match method.as_str() {
            "btree" => Ok(IndexMethod::BTree),
            "hash" => Ok(IndexMethod::Hash),
            "gin" | "inverted" => Ok(IndexMethod::Gin),
            "gist" => Ok(IndexMethod::Gist),
            "brin" | "summary" => Ok(IndexMethod::Brin),
            unknown => Err(self.error(format!("unsupported index method {unknown}"))),
        }
    }

    fn parse_alter(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Alter)?;
        self.expect_keyword(TokenKind::Table)?;
        let table = self.parse_object_name()?;
        match self.peek_kind() {
            Some(TokenKind::Add) => self.parse_alter_add_column_tail(table),
            Some(TokenKind::Alter) => self.parse_alter_column_encryption_tail(table),
            Some(kind) => Err(self.error(format!("unexpected ALTER TABLE action {kind:?}"))),
            None => Err(self.error("expected ALTER TABLE action")),
        }
    }

    fn parse_alter_add_column_tail(&mut self, table: ObjectName) -> Result<Statement> {
        self.expect_keyword(TokenKind::Add)?;
        self.expect_keyword(TokenKind::Column)?;
        let if_not_exists = if self.consume_if(&TokenKind::If) {
            self.expect_keyword(TokenKind::Not)?;
            self.expect_keyword(TokenKind::Exists)?;
            true
        } else {
            false
        };
        let column = self.parse_column_def()?;
        Ok(Statement::AlterTableAddColumn {
            table,
            column,
            if_not_exists,
        })
    }

    fn parse_alter_column_encryption_tail(&mut self, table: ObjectName) -> Result<Statement> {
        self.expect_keyword(TokenKind::Alter)?;
        self.expect_keyword(TokenKind::Column)?;
        let column = self.parse_ident()?;
        let encrypted = if self.consume_if(&TokenKind::Set) {
            self.expect_keyword(TokenKind::Encrypted)?;
            true
        } else if self.consume_if(&TokenKind::Drop) {
            self.expect_keyword(TokenKind::Encrypted)?;
            false
        } else {
            return Err(self.error("expected SET ENCRYPTED or DROP ENCRYPTED"));
        };
        Ok(Statement::AlterColumnEncryption {
            table,
            column,
            encrypted,
        })
    }

    fn parse_drop(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Drop)?;
        match self.peek_kind() {
            Some(TokenKind::Index) => self.parse_drop_index_tail(),
            Some(TokenKind::Trigger) => self.parse_drop_trigger_tail(),
            Some(TokenKind::Table) => self.parse_drop_table_tail(),
            Some(TokenKind::Function) => self.parse_drop_function_tail(),
            Some(TokenKind::Procedure) => self.parse_drop_procedure_tail(),
            Some(TokenKind::OperatorKeyword) => self.parse_drop_operator_tail(),
            Some(TokenKind::Role) => self.parse_drop_role_tail(),
            Some(TokenKind::Policy) => self.parse_drop_policy_tail(),
            _ => Err(self.error("expected object type after DROP")),
        }
    }

    fn parse_drop_index_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Index)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_object_name()?;
        Ok(Statement::DropIndex { name, if_exists })
    }

    fn parse_drop_trigger_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Trigger)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        Ok(Statement::DropTrigger {
            name,
            table,
            if_exists,
        })
    }

    fn parse_drop_table_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Table)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_object_name()?;
        Ok(Statement::DropTable { name, if_exists })
    }

    fn parse_drop_function_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Function)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = if self.consume_if(&TokenKind::RightParen) {
            Vec::new()
        } else {
            let types = self.parse_type_list()?;
            self.expect_keyword(TokenKind::RightParen)?;
            types
        };
        Ok(Statement::DropFunction {
            name,
            argument_types,
            if_exists,
        })
    }

    fn parse_drop_procedure_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Procedure)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = if self.consume_if(&TokenKind::RightParen) {
            Vec::new()
        } else {
            let types = self.parse_type_list()?;
            self.expect_keyword(TokenKind::RightParen)?;
            types
        };
        Ok(Statement::DropProcedure {
            name,
            argument_types,
            if_exists,
        })
    }

    fn parse_drop_operator_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::OperatorKeyword)?;
        let if_exists = self.parse_if_exists()?;
        let (symbol, left_type, right_type) = self.parse_drop_operator_signature()?;
        Ok(Statement::DropOperator {
            symbol,
            left_type,
            right_type,
            if_exists,
        })
    }

    fn parse_drop_operator_signature(&mut self) -> Result<(String, SqlType, SqlType)> {
        let symbol = self.parse_operator_symbol()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let left_type = self.parse_type()?;
        self.expect_keyword(TokenKind::Comma)?;
        let right_type = self.parse_type()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok((symbol, left_type, right_type))
    }

    fn parse_drop_role_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Role)?;
        let if_exists = self.parse_if_exists()?;
        Ok(Statement::DropRole {
            name: self.parse_ident()?,
            if_exists,
        })
    }

    fn parse_drop_policy_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Policy)?;
        let if_exists = self.parse_if_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        Ok(Statement::DropPolicy {
            name,
            table,
            if_exists,
        })
    }

    fn parse_if_exists(&mut self) -> Result<bool> {
        if self.consume_if(&TokenKind::If) {
            self.expect_keyword(TokenKind::Exists)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_column_def(&mut self) -> Result<ColumnDef> {
        let name = self.parse_ident()?;
        let data_type = self.parse_type()?;
        let options = self.parse_column_options()?;

        Ok(ColumnDef {
            name,
            data_type,
            nullable: options.nullable,
            encrypted: options.encrypted,
            generated: options.generated,
            references: options.references,
        })
    }

    fn parse_column_options(&mut self) -> Result<ColumnOptions> {
        let mut options = ColumnOptions::default();
        while self.parse_column_option(&mut options)? {}
        Ok(options)
    }

    fn parse_column_option(&mut self, options: &mut ColumnOptions) -> Result<bool> {
        match self.peek_kind() {
            Some(TokenKind::Not) => {
                self.bump();
                self.expect_keyword(TokenKind::Null)?;
                options.nullable = false;
            }
            Some(TokenKind::Encrypted) => {
                self.bump();
                options.encrypted = true;
            }
            Some(TokenKind::Generated) => self.parse_generated_column_option(options)?,
            Some(TokenKind::References) => self.parse_column_reference_option(options)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn parse_generated_column_option(&mut self, options: &mut ColumnOptions) -> Result<()> {
        self.ensure_column_option_absent(
            options.generated.is_some(),
            "column has duplicate generated expression",
        )?;
        self.bump();
        options.generated = Some(self.parse_stored_generated_column()?);
        Ok(())
    }

    fn parse_stored_generated_column(&mut self) -> Result<GeneratedColumn> {
        self.expect_keyword(TokenKind::Always)?;
        self.expect_keyword(TokenKind::As)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let expr = self.parse_expr()?;
        self.expect_keyword(TokenKind::RightParen)?;
        self.expect_keyword(TokenKind::Stored)?;
        Ok(GeneratedColumn { expr, stored: true })
    }

    fn parse_column_reference_option(&mut self, options: &mut ColumnOptions) -> Result<()> {
        self.ensure_column_option_absent(
            options.references.is_some(),
            "column has duplicate references clause",
        )?;
        options.references = Some(self.parse_column_reference()?);
        Ok(())
    }

    fn ensure_column_option_absent(&self, duplicate: bool, message: &str) -> Result<()> {
        if duplicate {
            return Err(self.error(message));
        }
        Ok(())
    }

    fn parse_column_reference(&mut self) -> Result<ColumnReference> {
        self.expect_keyword(TokenKind::References)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let column = self.parse_ident()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(ColumnReference { table, column })
    }

    fn parse_table_foreign_key(&mut self) -> Result<(Ident, ColumnReference)> {
        if !self.consume_identifier_keyword("foreign") {
            return Err(self.error("expected FOREIGN"));
        }
        if !self.consume_identifier_keyword("key") {
            return Err(self.error("expected KEY"));
        }
        self.expect_keyword(TokenKind::LeftParen)?;
        let columns = self.parse_ident_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        let [column] = columns.as_slice() else {
            return Err(self.error("table-level FOREIGN KEY supports exactly one column"));
        };
        let reference = self.parse_column_reference()?;
        Ok((column.clone(), reference))
    }

    fn apply_table_foreign_keys(
        &self,
        columns: &mut [ColumnDef],
        foreign_keys: Vec<(Ident, ColumnReference)>,
    ) -> Result<()> {
        for (column_name, reference) in foreign_keys {
            let Some(column) = columns.iter_mut().find(|column| column.name == column_name) else {
                return Err(self.error(format!(
                    "table-level FOREIGN KEY references unknown column {column_name}"
                )));
            };
            if column.references.is_some() {
                return Err(self.error(format!(
                    "column {} has duplicate references clause",
                    column.name
                )));
            }
            column.references = Some(reference);
        }
        Ok(())
    }

    fn parse_create_function_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Function)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let (name, argument_types, return_type) = self.parse_function_signature()?;
        let implementation = self.parse_create_function_implementation()?;
        Ok(Statement::CreateFunction {
            name,
            argument_types,
            return_type,
            implementation,
            if_not_exists,
        })
    }

    fn parse_function_signature(&mut self) -> Result<(Ident, Vec<SqlType>, SqlType)> {
        let name = self.parse_ident()?;
        let argument_types = self.parse_function_argument_types()?;
        self.expect_keyword(TokenKind::Returns)?;
        let return_type = self.parse_type()?;
        Ok((name, argument_types, return_type))
    }

    fn parse_function_argument_types(&mut self) -> Result<Vec<SqlType>> {
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = if self.consume_if(&TokenKind::RightParen) {
            Vec::new()
        } else {
            let types = self.parse_type_list()?;
            self.expect_keyword(TokenKind::RightParen)?;
            types
        };
        Ok(argument_types)
    }

    fn parse_create_function_implementation(&mut self) -> Result<CreateFunctionImplementation> {
        if !self.next_is_identifier_keyword("language") {
            return Ok(CreateFunctionImplementation::MetadataOnly);
        }
        self.parse_wasm_function_implementation()
    }

    fn parse_wasm_function_implementation(&mut self) -> Result<CreateFunctionImplementation> {
        self.parse_wasm_language()?;
        let module_bytes = self.parse_wasm_module_bytes()?;
        self.parse_wasm_options_clause(module_bytes)
            .map(CreateFunctionImplementation::Wasm)
    }

    fn parse_wasm_language(&mut self) -> Result<()> {
        self.expect_option_label("language")?;
        let language = self.parse_ident()?;
        if language.as_str() != "wasm" {
            return Err(self.error(format!(
                "unsupported function language {}",
                language.as_str()
            )));
        }
        Ok(())
    }

    fn parse_wasm_module_bytes(&mut self) -> Result<Vec<u8>> {
        self.expect_keyword(TokenKind::As)?;
        let encoded = self.parse_string_literal("wasm module hex")?;
        decode_wasm_module_hex(&encoded)
    }

    fn parse_wasm_options_clause(&mut self, module_bytes: Vec<u8>) -> Result<WasmFunctionBody> {
        self.expect_keyword(TokenKind::With)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let options = self.parse_wasm_function_options()?;
        self.expect_keyword(TokenKind::RightParen)?;
        options.into_body(module_bytes)
    }

    fn parse_wasm_function_options(&mut self) -> Result<WasmFunctionOptions> {
        let mut options = WasmFunctionOptions::default();
        loop {
            let name = self.parse_ident()?;
            self.expect_operator("=")?;
            let value = self.parse_positive_wasm_option(name.as_str())?;
            options.set(name.as_str(), value)?;
            if !self.consume_if(&TokenKind::Comma) {
                return Ok(options);
            }
        }
    }

    fn parse_positive_wasm_option(&mut self, name: &str) -> Result<u64> {
        let value = self.parse_row_count("wasm function option")?;
        if value == 0 {
            return Err(self.error(format!("wasm function option {name} must be positive")));
        }
        u64::try_from(value)
            .map_err(|_| self.error(format!("wasm function option {name} is too large")))
    }

    fn parse_create_procedure_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Procedure)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = self.parse_optional_type_list_body()?;
        self.expect_keyword(TokenKind::As)?;
        let body = self.parse_string_literal("procedure body")?;
        Ok(Statement::CreateProcedure {
            name,
            argument_types,
            body,
            if_not_exists,
        })
    }

    fn parse_optional_type_list_body(&mut self) -> Result<Vec<SqlType>> {
        if self.consume_if(&TokenKind::RightParen) {
            return Ok(Vec::new());
        }
        let types = self.parse_type_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(types)
    }

    fn parse_create_operator_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::OperatorKeyword)?;
        let signature = self.parse_create_operator_signature()?;
        let options = self.parse_create_operator_options()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Statement::CreateOperator {
            symbol: signature.symbol,
            left_type: signature.left_type,
            right_type: signature.right_type,
            result_type: signature.result_type,
            function: signature.function,
            precedence: options.precedence,
            commutator: options.commutator,
            negator: options.negator,
            selectivity: options.selectivity,
        })
    }

    fn parse_create_operator_signature(&mut self) -> Result<CreateOperatorSignature> {
        let (symbol, left_type, right_type) = self.parse_operator_operand_types()?;
        let (result_type, function) = self.parse_operator_result_and_function()?;
        Ok(CreateOperatorSignature {
            symbol,
            left_type,
            right_type,
            result_type,
            function,
        })
    }

    fn parse_operator_operand_types(&mut self) -> Result<(String, SqlType, SqlType)> {
        let symbol = self.parse_operator_symbol()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let left_type = self.parse_labeled_operator_type("leftarg")?;
        self.expect_keyword(TokenKind::Comma)?;
        let right_type = self.parse_labeled_operator_type("rightarg")?;
        self.expect_keyword(TokenKind::Comma)?;
        Ok((symbol, left_type, right_type))
    }

    fn parse_labeled_operator_type(&mut self, label: &str) -> Result<SqlType> {
        self.expect_option_label(label)?;
        self.expect_operator("=")?;
        self.parse_type()
    }

    fn parse_operator_result_and_function(&mut self) -> Result<(SqlType, Ident)> {
        self.expect_keyword(TokenKind::Returns)?;
        self.expect_operator("=")?;
        let result_type = self.parse_type()?;
        self.expect_keyword(TokenKind::Comma)?;
        self.expect_keyword(TokenKind::Function)?;
        self.expect_operator("=")?;
        let function = self.parse_ident()?;
        Ok((result_type, function))
    }

    fn parse_create_operator_options(&mut self) -> Result<CreateOperatorOptions> {
        let mut options = CreateOperatorOptions::default();
        while self.consume_if(&TokenKind::Comma) {
            self.parse_create_operator_option(&mut options)?;
        }
        Ok(options)
    }

    fn parse_create_operator_option(&mut self, options: &mut CreateOperatorOptions) -> Result<()> {
        let option = self.parse_ident()?;
        self.expect_operator("=")?;
        match option.as_str() {
            "precedence" => options.precedence = Some(self.parse_operator_precedence()?),
            "commutator" => options.commutator = Some(self.parse_operator_symbol()?),
            "negator" => options.negator = Some(self.parse_operator_symbol()?),
            "selectivity" => options.selectivity = Some(self.parse_ident()?),
            unknown => return Err(self.error(format!("unknown operator option {unknown}"))),
        }
        Ok(())
    }

    fn parse_operator_precedence(&mut self) -> Result<u8> {
        let value = self.parse_row_count("PRECEDENCE")?;
        u8::try_from(value)
            .map_err(|_| self.error("operator precedence must fit in an unsigned byte"))
    }

    fn parse_create_role_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Role)?;
        let if_not_exists = self.parse_if_not_exists()?;
        Ok(Statement::CreateRole {
            name: self.parse_ident()?,
            if_not_exists,
        })
    }

    fn parse_create_policy_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Policy)?;
        let if_not_exists = self.parse_if_not_exists()?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::Using)?;
        let predicate = self.parse_parenthesized_expr()?;
        Ok(Statement::CreatePolicy {
            name,
            table,
            predicate,
            if_not_exists,
        })
    }

    fn parse_parenthesized_expr(&mut self) -> Result<Expr> {
        self.expect_keyword(TokenKind::LeftParen)?;
        let predicate = self.parse_expr()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(predicate)
    }

    fn parse_if_not_exists(&mut self) -> Result<bool> {
        if self.consume_if(&TokenKind::If) {
            self.expect_keyword(TokenKind::Not)?;
            self.expect_keyword(TokenKind::Exists)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_grant(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Grant)?;
        let privilege = self.parse_privilege()?;
        self.expect_keyword(TokenKind::On)?;
        self.parse_grant_target(privilege)
    }

    fn parse_grant_target(&mut self, privilege: Privilege) -> Result<Statement> {
        if self.consume_if(&TokenKind::Table) {
            return self.parse_grant_table(privilege);
        }
        if self.consume_if(&TokenKind::Procedure) {
            return self.parse_grant_procedure(privilege);
        }
        Err(self.error("expected TABLE or PROCEDURE after GRANT privilege ON"))
    }

    fn parse_grant_table(&mut self, privilege: Privilege) -> Result<Statement> {
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::To)?;
        let role = self.parse_ident()?;
        Ok(Statement::GrantTablePrivilege {
            privilege,
            table,
            role,
        })
    }

    fn parse_grant_procedure(&mut self, privilege: Privilege) -> Result<Statement> {
        self.ensure_procedure_grant_privilege(privilege)?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = self.parse_optional_type_list_body()?;
        self.expect_keyword(TokenKind::To)?;
        let role = self.parse_ident()?;
        Ok(Statement::GrantProcedurePrivilege {
            privilege,
            name,
            argument_types,
            role,
        })
    }

    fn ensure_procedure_grant_privilege(&self, privilege: Privilege) -> Result<()> {
        if privilege != Privilege::Execute {
            return Err(self.error("expected EXECUTE privilege for procedure grant"));
        }
        Ok(())
    }

    fn parse_call_procedure(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Call)?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let args = if self.consume_if(&TokenKind::RightParen) {
            Vec::new()
        } else {
            let args = self.parse_expr_list()?;
            self.expect_keyword(TokenKind::RightParen)?;
            args
        };
        Ok(Statement::CallProcedure { name, args })
    }

    fn parse_insert(&mut self) -> Result<Statement> {
        let (table, columns) = self.parse_insert_target()?;
        let values = self.parse_insert_values()?;
        self.validate_insert_arity(&columns, &values)?;
        Ok(Statement::Insert {
            table,
            columns,
            values,
        })
    }

    fn parse_insert_target(&mut self) -> Result<(ObjectName, Vec<Ident>)> {
        self.expect_keyword(TokenKind::Insert)?;
        self.expect_keyword(TokenKind::Into)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let columns = self.parse_ident_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok((table, columns))
    }

    fn parse_insert_values(&mut self) -> Result<Vec<Expr>> {
        self.expect_keyword(TokenKind::Values)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let values = self.parse_expr_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(values)
    }

    fn validate_insert_arity(&self, columns: &[Ident], values: &[Expr]) -> Result<()> {
        if columns.len() != values.len() {
            return Err(self.error("insert column count does not match value count"));
        }
        Ok(())
    }

    fn parse_update(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Update)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::Set)?;
        let assignments = self.parse_assignment_list()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Statement::Update {
            table,
            assignments,
            selection,
        })
    }

    fn parse_delete(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Delete)?;
        self.expect_keyword(TokenKind::From)?;
        let table = self.parse_object_name()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Statement::Delete { table, selection })
    }

    fn parse_transaction(&mut self, action: TransactionAction) -> Result<Statement> {
        self.bump();
        Ok(Statement::Transaction { action })
    }

    fn parse_select_core(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Select)?;
        let distinct = self.consume_if(&TokenKind::Distinct);
        if !distinct {
            let _ = self.consume_if(&TokenKind::All);
        }
        let mut projection = Vec::new();
        loop {
            if self.consume_if(&TokenKind::Star) {
                projection.push(SelectItem::Wildcard);
            } else {
                let expr = self.parse_expr()?;
                let alias = if self.consume_if(&TokenKind::As) {
                    Some(self.parse_ident()?)
                } else {
                    None
                };
                projection.push(SelectItem::Expr { expr, alias });
            }
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        self.expect_keyword(TokenKind::From)?;
        let from = self.parse_object_name()?;
        let (join, lateral_join) = self.parse_select_join()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let (group_by, grouping_sets) = if self.consume_if(&TokenKind::Group) {
            self.expect_keyword(TokenKind::By)?;
            if self.consume_if(&TokenKind::Grouping) {
                self.expect_keyword(TokenKind::Sets)?;
                let grouping_sets = self.parse_grouping_sets()?;
                let group_by = grouping_sets_union(&grouping_sets);
                (group_by, grouping_sets)
            } else if self.consume_if(&TokenKind::Rollup) {
                let group_by = self.parse_parenthesized_expr_list()?;
                let grouping_sets = rollup_grouping_sets(&group_by);
                (group_by, grouping_sets)
            } else if self.consume_if(&TokenKind::Cube) {
                let group_by = self.parse_parenthesized_expr_list()?;
                let grouping_sets = cube_grouping_sets(&group_by)?;
                (group_by, grouping_sets)
            } else {
                (self.parse_expr_list()?, Vec::new())
            }
        } else {
            (Vec::new(), Vec::new())
        };
        let having = if self.consume_if(&TokenKind::Having) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        if (join.is_some() || lateral_join.is_some()) && !grouping_sets.is_empty() {
            return Err(self.error("JOIN does not support GROUPING SETS yet"));
        }
        if !grouping_sets.is_empty() {
            return Ok(Statement::SelectGroupingSets {
                distinct,
                projection,
                from,
                selection,
                group_by,
                grouping_sets,
                having,
                order_by: Vec::new(),
                limit: None,
                offset: None,
            });
        }
        if let Some(lateral_join) = lateral_join {
            Ok(Statement::SelectLateral {
                distinct,
                projection,
                from,
                lateral_join,
                selection,
                group_by,
                having,
                order_by: Vec::new(),
                limit: None,
                offset: None,
            })
        } else if let Some(join) = join {
            Ok(Statement::SelectJoin {
                distinct,
                projection,
                from,
                join,
                selection,
                group_by,
                having,
                order_by: Vec::new(),
                limit: None,
                offset: None,
            })
        } else {
            Ok(Statement::Select {
                distinct,
                projection,
                from,
                selection,
                group_by,
                having,
                order_by: Vec::new(),
                limit: None,
                offset: None,
            })
        }
    }

    fn parse_select_join(&mut self) -> Result<(Option<JoinClause>, Option<LateralJoin>)> {
        if self.consume_if(&TokenKind::Left) {
            let _ = self.consume_if(&TokenKind::Outer);
            return self
                .parse_join_clause(JoinKind::Left)
                .map(|join| (Some(join), None));
        }
        if self.consume_if(&TokenKind::Inner) {
            self.expect_keyword(TokenKind::Join)?;
            return self
                .parse_join_table(JoinKind::Inner)
                .map(|join| (Some(join), None));
        }
        if !self.consume_if(&TokenKind::Join) {
            return Ok((None, None));
        }
        if self.consume_if(&TokenKind::Lateral) {
            return self.parse_lateral_join().map(|join| (None, Some(join)));
        }
        self.parse_join_table(JoinKind::Inner)
            .map(|join| (Some(join), None))
    }

    fn parse_join_clause(&mut self, kind: JoinKind) -> Result<JoinClause> {
        self.expect_keyword(TokenKind::Join)?;
        self.parse_join_table(kind)
    }

    fn parse_join_table(&mut self, kind: JoinKind) -> Result<JoinClause> {
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::On)?;
        Ok(JoinClause {
            kind,
            table,
            on: self.parse_expr()?,
        })
    }

    fn parse_lateral_join(&mut self) -> Result<LateralJoin> {
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::On)?;
        Ok(LateralJoin {
            table,
            on: self.parse_expr()?,
        })
    }

    fn parse_query(&mut self) -> Result<Statement> {
        let mut statement = self.parse_select_core()?;
        let mut set_operation = false;
        loop {
            if self.consume_if(&TokenKind::Union) {
                let all = self.consume_if(&TokenKind::All);
                let right = self.parse_select_core()?;
                statement = Statement::Union {
                    all,
                    left: Box::new(statement),
                    right: Box::new(right),
                };
                set_operation = true;
            } else if self.consume_if(&TokenKind::Intersect) {
                let all = self.consume_if(&TokenKind::All);
                let right = self.parse_select_core()?;
                statement = Statement::Intersect {
                    all,
                    left: Box::new(statement),
                    right: Box::new(right),
                };
                set_operation = true;
            } else if self.consume_if(&TokenKind::Except) {
                let all = self.consume_if(&TokenKind::All);
                let right = self.parse_select_core()?;
                statement = Statement::Except {
                    all,
                    left: Box::new(statement),
                    right: Box::new(right),
                };
                set_operation = true;
            } else {
                break;
            }
        }
        let tail = self.parse_query_tail()?;
        Ok(apply_query_tail(statement, tail, set_operation))
    }

    fn parse_recursive_cte(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::With)?;
        self.expect_keyword(TokenKind::Recursive)?;
        let name = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let columns = self.parse_ident_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        self.expect_keyword(TokenKind::As)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let seed = self.parse_select_core()?;
        self.expect_keyword(TokenKind::Union)?;
        if !self.consume_if(&TokenKind::All) {
            return Err(self.error("recursive CTE requires UNION ALL"));
        }
        let recursive = self.parse_select_core()?;
        self.expect_keyword(TokenKind::RightParen)?;
        if columns.is_empty() {
            return Err(self.error("recursive CTE requires at least one output column"));
        }
        let query = self.parse_query()?;
        Ok(Statement::RecursiveCte {
            name,
            columns,
            seed: Box::new(seed),
            recursive: Box::new(recursive),
            query: Box::new(query),
        })
    }

    fn parse_object_name(&mut self) -> Result<ObjectName> {
        let first = self.parse_ident()?;
        self.parse_object_name_from_first(first)
    }

    fn parse_object_name_from_first(&mut self, first: Ident) -> Result<ObjectName> {
        if self.consume_if(&TokenKind::Dot) {
            let second = self.parse_ident()?;
            Ok(ObjectName::qualified(first.as_str(), second.as_str()))
        } else {
            Ok(ObjectName::unqualified(first.as_str()))
        }
    }

    fn parse_ident_list(&mut self) -> Result<Vec<Ident>> {
        let mut identifiers = Vec::new();
        loop {
            identifiers.push(self.parse_ident()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(identifiers)
    }

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>> {
        let mut expressions = Vec::new();
        loop {
            expressions.push(self.parse_expr()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(expressions)
    }

    fn parse_grouping_sets(&mut self) -> Result<Vec<Vec<Expr>>> {
        self.expect_keyword(TokenKind::LeftParen)?;
        let mut grouping_sets = Vec::new();
        loop {
            self.expect_keyword(TokenKind::LeftParen)?;
            let grouping_set = if self.consume_if(&TokenKind::RightParen) {
                Vec::new()
            } else {
                let expressions = self.parse_expr_list()?;
                self.expect_keyword(TokenKind::RightParen)?;
                expressions
            };
            grouping_sets.push(grouping_set);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        self.expect_keyword(TokenKind::RightParen)?;
        if grouping_sets.is_empty() {
            return Err(self.error("GROUPING SETS requires at least one grouping set"));
        }
        Ok(grouping_sets)
    }

    fn parse_parenthesized_expr_list(&mut self) -> Result<Vec<Expr>> {
        self.expect_keyword(TokenKind::LeftParen)?;
        let expressions = self.parse_expr_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(expressions)
    }

    fn parse_assignment_list(&mut self) -> Result<Vec<Assignment>> {
        let mut assignments = Vec::new();
        loop {
            let column = self.parse_ident()?;
            self.expect_operator("=")?;
            let value = self.parse_expr()?;
            assignments.push(Assignment { column, value });
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(assignments)
    }

    fn parse_type_list(&mut self) -> Result<Vec<SqlType>> {
        let mut types = Vec::new();
        loop {
            types.push(self.parse_type()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(types)
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_and_expr()?;
        while self.consume_if(&TokenKind::Or) {
            let right = self.parse_and_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: "OR".to_string(),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_and_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_not_expr()?;
        while self.consume_if(&TokenKind::And) {
            let right = self.parse_not_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: "AND".to_string(),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_not_expr(&mut self) -> Result<Expr> {
        if self.consume_if(&TokenKind::Not) {
            return Ok(Expr::Not(Box::new(self.parse_not_expr()?)));
        }
        self.parse_comparison_expr()
    }

    fn parse_comparison_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_concat_expr()?;
        if self.consume_if(&TokenKind::Is) {
            let negated = self.consume_if(&TokenKind::Not);
            if self.consume_if(&TokenKind::Distinct) {
                self.expect_keyword(TokenKind::From)?;
                let right = self.parse_additive_expr()?;
                return Ok(Expr::IsDistinctFrom {
                    left: Box::new(expr),
                    right: Box::new(right),
                    negated,
                });
            }
            if self.consume_if(&TokenKind::True) {
                return Ok(Expr::IsTruth {
                    expr: Box::new(expr),
                    value: true,
                    negated,
                });
            }
            if self.consume_if(&TokenKind::False) {
                return Ok(Expr::IsTruth {
                    expr: Box::new(expr),
                    value: false,
                    negated,
                });
            }
            if self.consume_if(&TokenKind::Unknown) {
                return Ok(Expr::IsUnknown {
                    expr: Box::new(expr),
                    negated,
                });
            }
            self.expect_keyword(TokenKind::Null)?;
            return Ok(Expr::IsNull {
                expr: Box::new(expr),
                negated,
            });
        }
        if self.consume_if(&TokenKind::Between) {
            return self.parse_between_tail(expr, false);
        }
        if self.consume_if(&TokenKind::In) {
            return self.parse_in_list_tail(expr, false);
        }
        if self.consume_if(&TokenKind::Like) {
            return self.parse_like_tail(expr, false);
        }
        if self.consume_if(&TokenKind::Not) {
            if self.consume_if(&TokenKind::Between) {
                return self.parse_between_tail(expr, true);
            }
            if self.consume_if(&TokenKind::In) {
                return self.parse_in_list_tail(expr, true);
            }
            self.expect_keyword(TokenKind::Like)?;
            return self.parse_like_tail(expr, true);
        }
        if let Some(TokenKind::Operator(op)) = self.peek_kind().cloned() {
            self.bump();
            let right = self.parse_concat_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_between_tail(&mut self, expr: Expr, negated: bool) -> Result<Expr> {
        let low = self.parse_concat_expr()?;
        self.expect_keyword(TokenKind::And)?;
        let high = self.parse_concat_expr()?;
        Ok(Expr::Between {
            expr: Box::new(expr),
            low: Box::new(low),
            high: Box::new(high),
            negated,
        })
    }

    fn parse_in_list_tail(&mut self, expr: Expr, negated: bool) -> Result<Expr> {
        self.expect_keyword(TokenKind::LeftParen)?;
        if self.consume_if(&TokenKind::RightParen) {
            return Err(self.error("IN requires at least one expression"));
        }
        if self.peek_kind() == Some(&TokenKind::Select) {
            return self.parse_in_subquery_tail(expr, negated);
        }
        let values = self.parse_expr_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::InList {
            expr: Box::new(expr),
            values,
            negated,
        })
    }

    fn parse_in_subquery_tail(&mut self, expr: Expr, negated: bool) -> Result<Expr> {
        let query = self.parse_query()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::InSubquery {
            expr: Box::new(expr),
            query: SelectSubquery::Parsed(Box::new(query)),
            negated,
        })
    }

    fn parse_like_tail(&mut self, expr: Expr, negated: bool) -> Result<Expr> {
        let pattern = self.parse_concat_expr()?;
        Ok(Expr::Like {
            expr: Box::new(expr),
            pattern: Box::new(pattern),
            negated,
        })
    }

    fn parse_concat_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_additive_expr()?;
        while let Some(TokenKind::Operator(op)) = self.peek_kind().cloned() {
            if op != "||" {
                break;
            }
            self.bump();
            let right = self.parse_additive_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_additive_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_multiplicative_expr()?;
        while let Some(TokenKind::Operator(op)) = self.peek_kind().cloned() {
            if !matches!(op.as_str(), "+" | "-") {
                break;
            }
            self.bump();
            let right = self.parse_multiplicative_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_multiplicative_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_unary_arithmetic_expr()?;
        loop {
            let op = match self.peek_kind().cloned() {
                Some(TokenKind::Star) => "*".to_string(),
                Some(TokenKind::Operator(op)) if matches!(op.as_str(), "/" | "%") => op,
                _ => break,
            };
            self.bump();
            let right = self.parse_unary_arithmetic_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_unary_arithmetic_expr(&mut self) -> Result<Expr> {
        if let Some(TokenKind::Operator(op)) = self.peek_kind().cloned()
            && matches!(op.as_str(), "+" | "-")
        {
            self.bump();
            return Ok(Expr::Unary {
                op,
                expr: Box::new(self.parse_unary_arithmetic_expr()?),
            });
        }
        self.parse_primary_expr()
    }

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Case) => self.parse_case_expr(),
            Some(TokenKind::Exists) => self.parse_exists_subquery_expr(),
            Some(TokenKind::Identifier(_)) => {
                let first = self.parse_ident()?;
                if first.as_str() == "array" && self.consume_if(&TokenKind::LeftBracket) {
                    let values = if self.consume_if(&TokenKind::RightBracket) {
                        Vec::new()
                    } else {
                        let values = self.parse_expr_list()?;
                        self.expect_keyword(TokenKind::RightBracket)?;
                        values
                    };
                    return Ok(Expr::Array(values));
                }
                if first.as_str() == "hstore" && self.consume_if(&TokenKind::LeftParen) {
                    return self.parse_hstore_literal_tail();
                }
                if first.as_str() == "range" && self.consume_if(&TokenKind::LeftParen) {
                    return self.parse_range_literal_tail();
                }
                if first.as_str() == "cast" && self.consume_if(&TokenKind::LeftParen) {
                    return self.parse_cast_expr_tail();
                }

                let name = self.parse_object_name_from_first(first)?;
                if self.consume_if(&TokenKind::LeftParen) {
                    if name.schema().is_none()
                        && name.object() == "count"
                        && self.consume_if(&TokenKind::Star)
                    {
                        self.expect_keyword(TokenKind::RightParen)?;
                        return Ok(Expr::CountStar);
                    }
                    let args = if self.consume_if(&TokenKind::RightParen) {
                        Vec::new()
                    } else if self.consume_if(&TokenKind::Distinct) {
                        let expr = self.parse_expr()?;
                        self.expect_keyword(TokenKind::RightParen)?;
                        if name.schema().is_none() && name.object() == "count" {
                            return Ok(Expr::CountDistinct(Box::new(expr)));
                        }
                        return Err(self.error(format!(
                            "DISTINCT arguments are not supported for function {name}"
                        )));
                    } else {
                        let args = self.parse_expr_list()?;
                        self.expect_keyword(TokenKind::RightParen)?;
                        args
                    };
                    if name.schema().is_none() && ranking_window_function(name.object()).is_some() {
                        if !args.is_empty() {
                            return Err(self
                                .error(format!("{}() does not accept arguments", name.object())));
                        }
                        let order_by = self.parse_window_order_by(name.object())?;
                        return Ok(ranking_window_function(name.object())
                            .expect("checked ranking window function")(
                            order_by
                        ));
                    }
                    if name.schema().is_none() && name.object() == "count" {
                        let mut args = args;
                        return Ok(Expr::Count(Box::new(
                            self.single_function_arg("count", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "sum" {
                        let mut args = args;
                        return Ok(Expr::Sum(Box::new(
                            self.single_function_arg("sum", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "min" {
                        let mut args = args;
                        return Ok(Expr::Min(Box::new(
                            self.single_function_arg("min", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "max" {
                        let mut args = args;
                        return Ok(Expr::Max(Box::new(
                            self.single_function_arg("max", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "coalesce" {
                        if args.is_empty() {
                            return Err(self.error("COALESCE requires at least one expression"));
                        }
                        return Ok(Expr::Coalesce(args));
                    }
                    if name.schema().is_none() && name.object() == "nullif" {
                        if args.len() != 2 {
                            return Err(self.error("NULLIF requires exactly two expressions"));
                        }
                        let mut args = args.into_iter();
                        let left = args.next().expect("NULLIF argument length checked");
                        let right = args.next().expect("NULLIF argument length checked");
                        return Ok(Expr::NullIf {
                            left: Box::new(left),
                            right: Box::new(right),
                        });
                    }
                    Ok(Expr::Call {
                        function_id: None,
                        name,
                        args,
                    })
                } else {
                    match name.schema() {
                        Some(qualifier) => Ok(Expr::QualifiedIdentifier {
                            qualifier: Ident::new(qualifier),
                            name: Ident::new(name.object()),
                        }),
                        None => Ok(Expr::Identifier(Ident::new(name.object()))),
                    }
                }
            }
            Some(TokenKind::Integer(value)) => {
                self.bump();
                Ok(Expr::Integer(value))
            }
            Some(TokenKind::Float64(value)) => {
                self.bump();
                Ok(Expr::Float64(value))
            }
            Some(TokenKind::String(value)) => {
                self.bump();
                Ok(Expr::String(value))
            }
            Some(TokenKind::True) => {
                self.bump();
                Ok(Expr::Bool(true))
            }
            Some(TokenKind::False) => {
                self.bump();
                Ok(Expr::Bool(false))
            }
            Some(TokenKind::Null) => {
                self.bump();
                Ok(Expr::Null)
            }
            Some(TokenKind::LeftParen) => {
                self.bump();
                if self.peek_kind() == Some(&TokenKind::Select) {
                    let query = self.parse_query()?;
                    self.expect_keyword(TokenKind::RightParen)?;
                    return Ok(Expr::ScalarSubquery {
                        query: SelectSubquery::Parsed(Box::new(query)),
                    });
                }
                let expr = self.parse_expr()?;
                self.expect_keyword(TokenKind::RightParen)?;
                Ok(expr)
            }
            Some(kind) => Err(self.error(format!("unexpected expression token {kind:?}"))),
            None => Err(self.error("expected expression")),
        }
    }

    fn parse_exists_subquery_expr(&mut self) -> Result<Expr> {
        self.expect_keyword(TokenKind::Exists)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let query = self.parse_query()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::ExistsSubquery {
            query: SelectSubquery::Parsed(Box::new(query)),
        })
    }

    fn parse_case_expr(&mut self) -> Result<Expr> {
        self.expect_keyword(TokenKind::Case)?;
        let operand = if self.consume_if(&TokenKind::When) {
            None
        } else {
            let operand = self.parse_expr()?;
            self.expect_keyword(TokenKind::When)?;
            Some(Box::new(operand))
        };

        let mut whens = Vec::new();
        loop {
            let condition = self.parse_expr()?;
            self.expect_keyword(TokenKind::Then)?;
            let result = self.parse_expr()?;
            whens.push(CaseWhen { condition, result });

            if !self.consume_if(&TokenKind::When) {
                break;
            }
        }

        let else_expr = if self.consume_if(&TokenKind::Else) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        self.expect_keyword(TokenKind::End)?;

        Ok(Expr::Case {
            operand,
            whens,
            else_expr,
        })
    }

    fn parse_hstore_literal_tail(&mut self) -> Result<Expr> {
        let mut entries = Vec::new();
        if self.consume_if(&TokenKind::RightParen) {
            return Ok(Expr::HStore(entries));
        }

        loop {
            let key = self.parse_string_literal("hstore key")?;
            self.expect_operator("=>")?;
            let value = if self.consume_if(&TokenKind::Null) {
                None
            } else {
                Some(self.parse_string_literal("hstore value")?)
            };
            entries.push((key, value));

            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }

        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::HStore(entries))
    }

    fn parse_range_literal_tail(&mut self) -> Result<Expr> {
        let lower = self.parse_expr()?;
        self.expect_keyword(TokenKind::Comma)?;
        let upper = self.parse_expr()?;
        self.expect_keyword(TokenKind::Comma)?;
        let raw_bounds = self.parse_string_literal("range bounds")?;
        let bounds = RangeLiteralBounds::parse(&raw_bounds)
            .ok_or_else(|| self.error("range bounds must be one of [], [), (], ()"))?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::Range {
            lower: Box::new(lower),
            upper: Box::new(upper),
            bounds,
        })
    }

    fn parse_cast_expr_tail(&mut self) -> Result<Expr> {
        let expr = self.parse_expr()?;
        self.expect_keyword(TokenKind::As)?;
        let data_type = self.parse_type()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::Cast {
            expr: Box::new(expr),
            data_type,
        })
    }

    fn parse_type(&mut self) -> Result<SqlType> {
        let type_name = self.parse_ident()?;
        let mut data_type = if type_name.as_str() == "range" {
            self.expect_operator("<")?;
            let element_type = self.parse_type()?;
            self.expect_operator(">")?;
            SqlType::Range(Box::new(element_type))
        } else {
            match type_name.as_str() {
                "bool" | "boolean" => SqlType::Bool,
                "int64" | "bigint" | "integer" => SqlType::Int64,
                "uint64" => SqlType::UInt64,
                "float" | "float64" => SqlType::Float64,
                "double" => {
                    let _ = self.consume_identifier_keyword("precision");
                    SqlType::Float64
                }
                "doubleprecision" => SqlType::Float64,
                "uuid" => SqlType::Uuid,
                "timestamp" | "datetime" => SqlType::Timestamp,
                "json" | "jsonb" => SqlType::Json,
                "text" | "string" | "varchar" => SqlType::Text,
                "bytes" | "bytea" => SqlType::Bytes,
                "hstore" => SqlType::HStore,
                "textvector" | "tsvector" => SqlType::TextVector,
                unknown => return Err(self.error(format!("unknown SQL type {unknown}"))),
            }
        };

        while self.consume_if(&TokenKind::LeftBracket) {
            self.expect_keyword(TokenKind::RightBracket)?;
            data_type = SqlType::Array(Box::new(data_type));
        }

        Ok(data_type)
    }

    fn parse_string_literal(&mut self, name: &'static str) -> Result<String> {
        match self.peek_kind().cloned() {
            Some(TokenKind::String(value)) => {
                self.bump();
                Ok(value)
            }
            Some(kind) => Err(self.error(format!("expected {name} but found {kind:?}"))),
            None => Err(self.error(format!("expected {name}"))),
        }
    }

    fn parse_order_by_list(&mut self) -> Result<Vec<OrderByExpr>> {
        let mut expressions = Vec::new();
        loop {
            let expr = self.parse_expr()?;
            let direction = if self.consume_if(&TokenKind::Desc) {
                SortDirection::Desc
            } else {
                let _ = self.consume_if(&TokenKind::Asc);
                SortDirection::Asc
            };
            let direction = if self.consume_if(&TokenKind::Nulls) {
                if self.consume_if(&TokenKind::First) {
                    sort_direction_with_nulls(direction, true)
                } else {
                    self.expect_keyword(TokenKind::Last)?;
                    sort_direction_with_nulls(direction, false)
                }
            } else {
                direction
            };
            expressions.push(OrderByExpr { expr, direction });
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(expressions)
    }

    fn parse_window_order_by(&mut self, function_name: &str) -> Result<Vec<OrderByExpr>> {
        self.expect_keyword(TokenKind::Over)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        self.expect_keyword(TokenKind::Order)?;
        self.expect_keyword(TokenKind::By)?;
        let order_by = self.parse_order_by_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        if order_by.is_empty() {
            return Err(self.error(format!("{function_name}() OVER requires ORDER BY")));
        }
        Ok(order_by)
    }

    fn parse_query_tail(&mut self) -> Result<QueryTail> {
        let order_by = if self.consume_if(&TokenKind::Order) {
            self.expect_keyword(TokenKind::By)?;
            self.parse_order_by_list()?
        } else {
            Vec::new()
        };
        let limit = if self.consume_if(&TokenKind::Limit) {
            self.parse_limit_count()?
        } else {
            None
        };
        let offset = if self.consume_if(&TokenKind::Offset) {
            Some(self.parse_offset_count()?)
        } else {
            None
        };
        let fetch = self.parse_fetch_count()?;
        if limit.is_some() && fetch.is_some() {
            return Err(self.error("LIMIT and FETCH cannot be used together"));
        }
        Ok(QueryTail {
            order_by,
            limit: limit.or(fetch),
            offset,
        })
    }

    fn parse_limit_count(&mut self) -> Result<Option<usize>> {
        if self.consume_if(&TokenKind::All) {
            Ok(None)
        } else {
            self.parse_row_count("LIMIT").map(Some)
        }
    }

    fn parse_fetch_count(&mut self) -> Result<Option<usize>> {
        if !self.consume_if(&TokenKind::Fetch) {
            return Ok(None);
        }
        if !self.consume_if(&TokenKind::First) {
            self.expect_keyword(TokenKind::Next)?;
        }
        let count = if matches!(self.peek_kind(), Some(TokenKind::Row | TokenKind::Rows)) {
            1
        } else {
            self.parse_row_count("FETCH")?
        };
        if !self.consume_if(&TokenKind::Row) {
            self.expect_keyword(TokenKind::Rows)?;
        }
        self.expect_keyword(TokenKind::Only)?;
        Ok(Some(count))
    }

    fn parse_offset_count(&mut self) -> Result<usize> {
        let count = self.parse_row_count("OFFSET")?;
        if !self.consume_if(&TokenKind::Row) {
            let _ = self.consume_if(&TokenKind::Rows);
        }
        Ok(count)
    }

    fn parse_row_count(&mut self, clause: &'static str) -> Result<usize> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Integer(value)) => {
                self.bump();
                usize::try_from(value)
                    .map_err(|_| self.error(format!("{clause} must be a non-negative integer")))
            }
            Some(kind) => Err(self.error(format!("expected {clause} value but found {kind:?}"))),
            None => Err(self.error(format!("expected {clause} value"))),
        }
    }

    fn parse_privilege(&mut self) -> Result<Privilege> {
        match self.peek_kind() {
            Some(TokenKind::Select) => {
                self.bump();
                Ok(Privilege::Select)
            }
            Some(TokenKind::Insert) => {
                self.bump();
                Ok(Privilege::Insert)
            }
            Some(TokenKind::Update) => {
                self.bump();
                Ok(Privilege::Update)
            }
            Some(TokenKind::Delete) => {
                self.bump();
                Ok(Privilege::Delete)
            }
            Some(TokenKind::Execute) => {
                self.bump();
                Ok(Privilege::Execute)
            }
            Some(kind) => Err(self.error(format!("expected privilege but found {kind:?}"))),
            None => Err(self.error("expected privilege")),
        }
    }

    fn single_function_arg(&self, name: &'static str, args: &mut Vec<Expr>) -> Result<Expr> {
        if args.len() != 1 {
            return Err(self.error(format!("{name}() requires exactly one expression")));
        }
        Ok(args.pop().expect("argument length checked"))
    }

    fn parse_operator_symbol(&mut self) -> Result<String> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Operator(symbol)) => {
                self.bump();
                Ok(symbol)
            }
            Some(TokenKind::Identifier(symbol)) => {
                self.bump();
                Ok(symbol)
            }
            Some(kind) => Err(self.error(format!("expected operator symbol but found {kind:?}"))),
            None => Err(self.error("expected operator symbol")),
        }
    }

    fn expect_operator(&mut self, expected: &str) -> Result<()> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Operator(op)) if op == expected => {
                self.bump();
                Ok(())
            }
            Some(kind) => {
                Err(self.error(format!("expected operator {expected} but found {kind:?}")))
            }
            None => Err(self.error(format!("expected operator {expected}"))),
        }
    }

    fn expect_option_label(&mut self, expected: &str) -> Result<()> {
        let ident = self.parse_ident()?;
        if ident.as_str() == expected {
            Ok(())
        } else {
            Err(self.error(format!("expected option {expected}")))
        }
    }

    fn parse_ident(&mut self) -> Result<Ident> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Identifier(value)) => {
                self.bump();
                Ok(Ident::new(value))
            }
            Some(kind) => Err(self.error(format!("expected identifier but found {kind:?}"))),
            None => Err(self.error("expected identifier")),
        }
    }

    fn expect_keyword(&mut self, expected: TokenKind) -> Result<()> {
        if self.consume_if(&expected) {
            Ok(())
        } else {
            Err(self.error(format!("expected {expected:?}")))
        }
    }

    fn consume_optional_semicolon(&mut self) {
        let _ = self.consume_if(&TokenKind::Semicolon);
    }

    fn expect_end(&self) -> Result<()> {
        if self.position == self.tokens.len() {
            Ok(())
        } else {
            Err(self.error("unexpected trailing tokens"))
        }
    }

    fn consume_if(&mut self, expected: &TokenKind) -> bool {
        let Some(actual) = self.peek_kind() else {
            return false;
        };
        if same_token_variant(actual, expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn consume_identifier_keyword(&mut self, expected: &str) -> bool {
        let Some(TokenKind::Identifier(value)) = self.peek_kind() else {
            return false;
        };
        if value == expected {
            self.bump();
            true
        } else {
            false
        }
    }

    fn next_is_identifier_keyword(&self, expected: &str) -> bool {
        matches!(
            self.peek_kind(),
            Some(TokenKind::Identifier(value)) if value == expected
        )
    }

    fn bump(&mut self) {
        self.position += 1;
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.position).map(Token::kind)
    }

    fn error(&self, message: impl Into<String>) -> RnovError {
        RnovError::new(ErrorKind::InvalidInput, message)
    }
}

fn required_wasm_option(value: Option<u64>, name: &str) -> Result<u64> {
    value.ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("missing wasm function option {name}"),
        )
    })
}

fn decode_wasm_module_hex(encoded: &str) -> Result<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm module hex must contain an even number of digits",
        ));
    }
    let byte_len = encoded.len() / 2;
    if byte_len > MAX_WASM_FUNCTION_MODULE_BYTES {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("wasm module exceeds the {MAX_WASM_FUNCTION_MODULE_BYTES}-byte input limit"),
        ));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| decode_hex_pair(pair, index * 2))
        .collect()
}

fn decode_hex_pair(pair: &[u8], offset: usize) -> Result<u8> {
    let high = decode_hex_nibble(pair[0], offset)?;
    let low = decode_hex_nibble(pair[1], offset + 1)?;
    Ok((high << 4) | low)
}

fn decode_hex_nibble(byte: u8, offset: usize) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("invalid wasm module hex digit at offset {offset}"),
        )),
    }
}

fn same_token_variant(left: &TokenKind, right: &TokenKind) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

fn apply_query_tail(statement: Statement, tail: QueryTail, set_operation: bool) -> Statement {
    if tail.is_empty() {
        return statement;
    }
    if set_operation {
        return Statement::Query {
            input: Box::new(statement),
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        };
    }
    match statement {
        Statement::Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
            ..
        } => Statement::Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        },
        Statement::SelectJoin {
            distinct,
            projection,
            from,
            join,
            selection,
            group_by,
            having,
            ..
        } => Statement::SelectJoin {
            distinct,
            projection,
            from,
            join,
            selection,
            group_by,
            having,
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        },
        Statement::SelectLateral {
            distinct,
            projection,
            from,
            lateral_join,
            selection,
            group_by,
            having,
            ..
        } => Statement::SelectLateral {
            distinct,
            projection,
            from,
            lateral_join,
            selection,
            group_by,
            having,
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        },
        Statement::SelectGroupingSets {
            distinct,
            projection,
            from,
            selection,
            group_by,
            grouping_sets,
            having,
            ..
        } => Statement::SelectGroupingSets {
            distinct,
            projection,
            from,
            selection,
            group_by,
            grouping_sets,
            having,
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        },
        other => Statement::Query {
            input: Box::new(other),
            order_by: tail.order_by,
            limit: tail.limit,
            offset: tail.offset,
        },
    }
}

fn ranking_window_function(name: &str) -> Option<fn(Vec<OrderByExpr>) -> Expr> {
    match name {
        "row_number" => Some(|order_by| Expr::RowNumberOver { order_by }),
        "rank" => Some(|order_by| Expr::RankOver { order_by }),
        "dense_rank" => Some(|order_by| Expr::DenseRankOver { order_by }),
        _ => None,
    }
}

fn sort_direction_with_nulls(direction: SortDirection, nulls_first: bool) -> SortDirection {
    match (direction, nulls_first) {
        (SortDirection::Asc | SortDirection::AscNullsFirst | SortDirection::AscNullsLast, true) => {
            SortDirection::AscNullsFirst
        }
        (
            SortDirection::Asc | SortDirection::AscNullsFirst | SortDirection::AscNullsLast,
            false,
        ) => SortDirection::AscNullsLast,
        (
            SortDirection::Desc | SortDirection::DescNullsFirst | SortDirection::DescNullsLast,
            true,
        ) => SortDirection::DescNullsFirst,
        (
            SortDirection::Desc | SortDirection::DescNullsFirst | SortDirection::DescNullsLast,
            false,
        ) => SortDirection::DescNullsLast,
    }
}
