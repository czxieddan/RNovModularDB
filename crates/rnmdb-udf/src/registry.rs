// crates/rnmdb-udf/src/registry.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: September 17, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.1.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
use rnmdb_common::{ErrorKind, Result, RnovError, ids::FunctionId};
use rnmdb_types::SqlType;

use super::{FunctionClass, UdfDefinition};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdfRegistry {
    next_function_id: Option<u64>,
    functions: Vec<UdfDefinition>,
}

impl Default for UdfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UdfRegistry {
    pub fn new() -> Self {
        Self {
            next_function_id: Some(1),
            functions: Vec::new(),
        }
    }

    pub fn register(&mut self, definition: UdfDefinition) -> Result<FunctionId> {
        let function_id = self.next_function_id.map(FunctionId::new).ok_or_else(|| {
            RnovError::new(ErrorKind::InvalidInput, "function id space is exhausted")
        })?;
        self.register_with_id(function_id, definition)
    }

    pub fn register_with_id(
        &mut self,
        function_id: FunctionId,
        definition: UdfDefinition,
    ) -> Result<FunctionId> {
        self.validate_registration(function_id, &definition)?;
        self.advance_next_function_id(function_id);
        self.functions
            .push(definition.with_function_id(function_id));
        Ok(function_id)
    }

    pub fn unregister(&mut self, function_id: FunctionId) -> Option<UdfDefinition> {
        let position = self
            .functions
            .iter()
            .position(|function| function.function_id == function_id)?;
        Some(self.functions.remove(position))
    }

    fn validate_registration(
        &self,
        function_id: FunctionId,
        definition: &UdfDefinition,
    ) -> Result<()> {
        if function_id.get() == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "function id must be greater than zero",
            ));
        }
        if self
            .functions
            .iter()
            .any(|function| function.function_id == function_id)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function id already exists: {}", function_id.get()),
            ));
        }
        if self.functions.iter().any(|function| {
            function.name == definition.name && function.argument_types == definition.argument_types
        }) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function already exists: {}", definition.name),
            ));
        }
        Ok(())
    }

    fn advance_next_function_id(&mut self, function_id: FunctionId) {
        let Some(next_function_id) = self.next_function_id else {
            return;
        };
        if function_id.get() >= next_function_id {
            self.next_function_id = function_id.get().checked_add(1);
        }
    }

    pub fn resolve_by_id(&self, function_id: FunctionId) -> Option<&UdfDefinition> {
        self.functions
            .iter()
            .find(|function| function.function_id == function_id)
    }

    pub fn resolve(&self, name: &str, argument_types: &[SqlType]) -> Option<&UdfDefinition> {
        self.functions
            .iter()
            .find(|function| function.name == name && function.argument_types == argument_types)
    }

    pub fn resolve_class(
        &self,
        name: &str,
        argument_types: &[SqlType],
        class: FunctionClass,
    ) -> Option<&UdfDefinition> {
        self.functions.iter().find(|function| {
            function.name == name
                && function.argument_types == argument_types
                && function.class() == class
        })
    }

    pub fn functions(&self) -> &[UdfDefinition] {
        &self.functions
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}
