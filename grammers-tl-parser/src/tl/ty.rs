// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;
use std::str::FromStr;

use crate::errors::ParamParseError;

/// The type of a definition or a parameter.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Type {
    /// The full name of this type.
    pub(crate) full_name: String,

    /// Optimization to quickly query the name part from the full name.
    pub(crate) name_start_idx: usize,

    /// Whether this type is bare or boxed.
    pub bare: bool,

    /// Whether the type name refers to a generic definition.
    pub generic_ref: bool,

    /// If the type has a generic argument, which is its type.
    pub generic_arg: Option<Box<Type>>,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.generic_ref {
            write!(f, "!")?;
        }
        write!(f, "{}", self.full_name)?;
        if let Some(generic_arg) = &self.generic_arg {
            write!(f, "<{generic_arg}>")?;
        }
        Ok(())
    }
}

impl Type {
    /// The dot-separated namespace string, if any.
    ///
    /// To date, no Telegram types contain a nested namespace.
    pub fn namespace(&self) -> Option<&str> {
        self.name_start_idx
            .checked_sub(1)
            .map(|i| &self.full_name[..i])
    }

    // The name of this type.
    pub fn name(&self) -> &str {
        &self.full_name[self.name_start_idx..]
    }

    /// The full name of this type, with namespace and name joined by a dot.
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Find all the nested generic references in this type, and appends them
    /// to the input vector.Box
    pub(crate) fn find_generic_refs<'a>(&'a self, output: &mut Vec<&'a str>) {
        if self.generic_ref {
            output.push(&self.full_name);
        }
        if let Some(generic_arg) = &self.generic_arg {
            generic_arg.find_generic_refs(output);
        }
    }
}

impl FromStr for Type {
    type Err = ParamParseError;

    /// Parses a type.
    ///
    /// # Examples
    ///
    /// ```
    /// use grammers_tl_parser::tl::Type;
    ///
    /// assert!("vector<int>".parse::<Type>().is_ok());
    /// ```
    fn from_str(ty: &str) -> Result<Self, Self::Err> {
        // Parse `!type`
        let (ty, generic_ref) = match ty.strip_prefix('!') {
            Some(ty) => (ty, true),
            None => (ty, false),
        };

        // Parse `type<generic_arg>`
        let (name, generic_arg) = match ty.split_once('<') {
            Some((name, generic_arg)) => match generic_arg.strip_suffix('>') {
                Some(generic_arg) => (name, Some(Box::new(Type::from_str(generic_arg)?))),
                None => return Err(ParamParseError::InvalidGeneric),
            },
            None => (ty, None),
        };

        // Parse `ns1.ns2.name`
        if name.split('.').any(|part| part.is_empty()) {
            return Err(ParamParseError::Empty);
        }
        let name_start_idx = name.rfind('.').map(|i| i + 1).unwrap_or_default();

        let Some(first_name_char) = name[name_start_idx..].chars().next() else {
            return Err(ParamParseError::Empty);
        };

        let bare = first_name_char.is_ascii_lowercase();

        Ok(Self {
            full_name: name.to_owned(),
            name_start_idx,
            bare,
            generic_ref,
            generic_arg,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_empty_simple() {
        assert_eq!(Type::from_str(""), Err(ParamParseError::Empty));
    }

    #[test]
    fn check_simple() {
        assert_eq!(
            Type::from_str("foo"),
            Ok(Type {
                full_name: "foo".into(),
                name_start_idx: 0,
                bare: true,
                generic_ref: false,
                generic_arg: None,
            })
        );
    }

    #[test]
    fn check_empty_namespaced() {
        assert_eq!(Type::from_str("."), Err(ParamParseError::Empty));
        assert_eq!(Type::from_str(".."), Err(ParamParseError::Empty));
        assert_eq!(Type::from_str(".foo"), Err(ParamParseError::Empty));
        assert_eq!(Type::from_str("foo."), Err(ParamParseError::Empty));
        assert_eq!(Type::from_str("foo..foo"), Err(ParamParseError::Empty));
        assert_eq!(Type::from_str(".foo."), Err(ParamParseError::Empty));
    }

    #[test]
    fn check_namespaced() {
        assert_eq!(
            Type::from_str("foo.bar.baz"),
            Ok(Type {
                full_name: "foo.bar.baz".into(),
                name_start_idx: 8,
                bare: true,
                generic_ref: false,
                generic_arg: None,
            })
        );
    }

    #[test]
    fn check_bare() {
        assert!(matches!(Type::from_str("foo"), Ok(Type { bare: true, .. })));
        assert!(matches!(
            Type::from_str("Foo"),
            Ok(Type { bare: false, .. })
        ));
        assert!(matches!(
            Type::from_str("Foo.bar"),
            Ok(Type { bare: true, .. })
        ));
        assert!(matches!(
            Type::from_str("Foo.Bar"),
            Ok(Type { bare: false, .. })
        ));
        assert!(matches!(
            Type::from_str("foo.Bar"),
            Ok(Type { bare: false, .. })
        ));
        assert!(matches!(
            Type::from_str("!bar"),
            Ok(Type { bare: true, .. })
        ));
        assert!(matches!(
            Type::from_str("!foo.Bar"),
            Ok(Type { bare: false, .. })
        ));
    }

    #[test]
    fn check_generic_ref() {
        assert!(matches!(
            Type::from_str("f"),
            Ok(Type {
                generic_ref: false,
                ..
            })
        ));
        assert!(matches!(
            Type::from_str("!f"),
            Ok(Type {
                generic_ref: true,
                ..
            })
        ));
        assert!(matches!(
            Type::from_str("!Foo"),
            Ok(Type {
                generic_ref: true,
                ..
            })
        ));
        assert!(matches!(
            Type::from_str("!X"),
            Ok(Type {
                generic_ref: true,
                ..
            })
        ));
    }

    #[test]
    fn check_generic_arg() {
        assert!(matches!(
            Type::from_str("foo.bar"),
            Ok(Type {
                generic_arg: None,
                ..
            })
        ));
        assert!(matches!(
            Type::from_str("foo<bar>"),
            Ok(Type {
                generic_arg: Some(x),
                ..
            }) if *x == "bar".parse().unwrap(),
        ));
        assert!(matches!(
            Type::from_str("foo<bar.Baz>"),
            Ok(Type {
                generic_arg: Some(x),
                ..
            }) if *x == "bar.Baz".parse().unwrap(),
        ));
        assert!(matches!(
            Type::from_str("foo<!bar.baz>"),
            Ok(Type {
                generic_arg: Some(x),
                ..
            }) if *x == "!bar.baz".parse().unwrap(),
        ));
        assert!(matches!(
            Type::from_str("foo<bar<baz>>"),
            Ok(Type {
                generic_arg: Some(x),
                ..
            }) if *x == "bar<baz>".parse().unwrap(),
        ));
    }
}
