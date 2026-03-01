package schema

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullIntrospectionFixture is a complete introspection response with multiple types,
// including deprecated fields, enum types, and interface types.
const fullIntrospectionFixture = `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": { "name": "Mutation" },
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "The root query type",
          "fields": [
            {
              "name": "user",
              "description": "Get a user by ID",
              "args": [
                {
                  "name": "id",
                  "description": "User ID",
                  "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } },
                  "defaultValue": null
                }
              ],
              "type": { "kind": "OBJECT", "name": "User", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "legacyUser",
              "description": "Legacy user lookup",
              "args": [],
              "type": { "kind": "OBJECT", "name": "User", "ofType": null },
              "isDeprecated": true,
              "deprecationReason": "Use user instead"
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "OBJECT",
          "name": "Mutation",
          "description": "The root mutation type",
          "fields": [
            {
              "name": "createUser",
              "description": "",
              "args": [],
              "type": { "kind": "OBJECT", "name": "User", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "OBJECT",
          "name": "User",
          "description": "A user in the system",
          "fields": [
            {
              "name": "id",
              "description": "Unique identifier",
              "args": [],
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "email",
              "description": "User email address",
              "args": [],
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "oldField",
              "description": "No longer used",
              "args": [],
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "isDeprecated": true,
              "deprecationReason": "Removed in v2"
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "ENUM",
          "name": "UserRole",
          "description": "Possible user roles",
          "fields": null,
          "inputFields": null,
          "interfaces": [],
          "enumValues": [
            { "name": "ADMIN", "description": "", "isDeprecated": false, "deprecationReason": null },
            { "name": "USER",  "description": "", "isDeprecated": false, "deprecationReason": null }
          ],
          "possibleTypes": null
        },
        {
          "kind": "SCALAR",
          "name": "__Schema",
          "description": "Built-in type that should be filtered",
          "fields": null,
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        }
      ],
      "directives": [
        {
          "name": "deprecated",
          "description": "Marks a field as deprecated",
          "locations": ["FIELD_DEFINITION", "ENUM_VALUE"],
          "args": [
            {
              "name": "reason",
              "description": "Why deprecated",
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "defaultValue": "No longer supported"
            }
          ]
        }
      ]
    }
  }
}`

func TestNormalize_FullResponse(t *testing.T) {
	schema, err := Normalize(json.RawMessage(fullIntrospectionFixture))
	require.NoError(t, err)
	require.NotNil(t, schema)

	// Built-in type __Schema must be excluded.
	assert.NotContains(t, schema.Types, "__Schema", "built-in types must be filtered")

	// Expect 4 user types: Query, Mutation, User, UserRole.
	assert.Len(t, schema.Types, 4, "should have exactly 4 user-defined types")

	// QueryType must be set.
	require.NotNil(t, schema.QueryType)
	assert.Equal(t, "Query", schema.QueryType.Name)

	// MutationType must be set.
	require.NotNil(t, schema.MutationType)
	assert.Equal(t, "Mutation", schema.MutationType.Name)

	// SubscriptionType must be nil.
	assert.Nil(t, schema.SubscriptionType)

	// Query type must have 2 fields (user + legacyUser).
	require.Len(t, schema.QueryType.Fields, 2)

	// Deprecated field must be marked.
	var deprecatedFound bool
	for _, f := range schema.QueryType.Fields {
		if f.Name == "legacyUser" {
			assert.True(t, f.IsDeprecated)
			assert.Equal(t, "Use user instead", f.DeprecationReason)
			deprecatedFound = true
		}
	}
	assert.True(t, deprecatedFound, "legacyUser deprecated field must be present")

	// User type fields.
	userType, ok := schema.Types["User"]
	require.True(t, ok)
	assert.Len(t, userType.Fields, 3)

	// Enum type values.
	roleType, ok := schema.Types["UserRole"]
	require.True(t, ok)
	assert.Equal(t, KindEnum, roleType.Kind)
	assert.ElementsMatch(t, []string{"ADMIN", "USER"}, roleType.EnumValues)

	// Directives.
	require.Len(t, schema.Directives, 1)
	assert.Equal(t, "deprecated", schema.Directives[0].Name)
}

func TestNormalize_NullMutationType(t *testing.T) {
	fixture := `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "",
          "fields": [],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        }
      ],
      "directives": []
    }
  }
}`
	schema, err := Normalize(json.RawMessage(fixture))
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.Nil(t, schema.MutationType, "MutationType must be nil when mutationType is null in response")
}

func TestNormalize_DeeplyNestedTypeRef(t *testing.T) {
	// A TypeRef with 5 levels: NON_NULL -> LIST -> NON_NULL -> LIST -> NON_NULL -> SCALAR "String"
	fixture := `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "",
          "fields": [
            {
              "name": "deepField",
              "description": "",
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "LIST",
                  "name": null,
                  "ofType": {
                    "kind": "NON_NULL",
                    "name": null,
                    "ofType": {
                      "kind": "LIST",
                      "name": null,
                      "ofType": {
                        "kind": "NON_NULL",
                        "name": null,
                        "ofType": {
                          "kind": "SCALAR",
                          "name": "String",
                          "ofType": null
                        }
                      }
                    }
                  }
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        }
      ],
      "directives": []
    }
  }
}`
	schema, err := Normalize(json.RawMessage(fixture))
	require.NoError(t, err)
	require.NotNil(t, schema)

	qt := schema.QueryType
	require.NotNil(t, qt)
	require.Len(t, qt.Fields, 1)

	deepField := qt.Fields[0]
	assert.Equal(t, "deepField", deepField.Name)
	require.NotNil(t, deepField.Type)

	// Unwrap should follow all 5 levels and return the "String" SCALAR.
	innermost := deepField.Type.Unwrap()
	require.NotNil(t, innermost)
	assert.Equal(t, "String", innermost.Name)
	assert.Equal(t, KindScalar, innermost.Kind)
}

// TestNormalize_EnumWithDeprecatedValue_TypeNotDeprecated verifies that a TypeDef is NOT
// marked IsDeprecated merely because one of its enum values is deprecated.
func TestNormalize_EnumWithDeprecatedValue_TypeNotDeprecated(t *testing.T) {
	fixture := `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "",
          "fields": [],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "ENUM",
          "name": "Status",
          "description": "Entity status",
          "fields": null,
          "inputFields": null,
          "interfaces": [],
          "enumValues": [
            { "name": "ACTIVE",   "description": "", "isDeprecated": false, "deprecationReason": null },
            { "name": "LEGACY",   "description": "", "isDeprecated": true,  "deprecationReason": "Use INACTIVE" },
            { "name": "INACTIVE", "description": "", "isDeprecated": false, "deprecationReason": null }
          ],
          "possibleTypes": null
        }
      ],
      "directives": []
    }
  }
}`
	schema, err := Normalize(json.RawMessage(fixture))
	require.NoError(t, err)
	require.NotNil(t, schema)

	statusType, ok := schema.Types["Status"]
	require.True(t, ok, "Status type must exist")
	assert.ElementsMatch(t, []string{"ACTIVE", "LEGACY", "INACTIVE"}, statusType.EnumValues)
	assert.False(t, statusType.IsDeprecated,
		"TypeDef.IsDeprecated must not be set because an enum VALUE is deprecated — only the type itself can be deprecated")
}

// TestNormalize_DefaultValue_NullVsEmpty verifies that a null defaultValue and an explicit
// empty-string defaultValue remain distinguishable after normalization.
func TestNormalize_DefaultValue_NullVsEmpty(t *testing.T) {
	fixture := `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "",
          "fields": [
            {
              "name": "search",
              "description": "",
              "args": [
                {
                  "name": "required",
                  "description": "No default value (null)",
                  "type": { "kind": "SCALAR", "name": "String", "ofType": null },
                  "defaultValue": null
                },
                {
                  "name": "withEmpty",
                  "description": "Explicit empty-string default",
                  "type": { "kind": "SCALAR", "name": "String", "ofType": null },
                  "defaultValue": ""
                },
                {
                  "name": "withValue",
                  "description": "Non-empty default",
                  "type": { "kind": "SCALAR", "name": "String", "ofType": null },
                  "defaultValue": "hello"
                }
              ],
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        }
      ],
      "directives": []
    }
  }
}`
	schema, err := Normalize(json.RawMessage(fixture))
	require.NoError(t, err)
	require.NotNil(t, schema)

	require.NotNil(t, schema.QueryType)
	require.Len(t, schema.QueryType.Fields, 1)
	args := schema.QueryType.Fields[0].Args
	require.Len(t, args, 3)

	argsByName := make(map[string]*ArgDef, len(args))
	for _, a := range args {
		argsByName[a.Name] = a
	}

	// null defaultValue → ArgDef.DefaultValue must be nil.
	required := argsByName["required"]
	require.NotNil(t, required)
	assert.Nil(t, required.DefaultValue, "null defaultValue must produce nil *string")

	// "" defaultValue → ArgDef.DefaultValue must be non-nil, pointing to "".
	withEmpty := argsByName["withEmpty"]
	require.NotNil(t, withEmpty)
	require.NotNil(t, withEmpty.DefaultValue, "empty-string defaultValue must produce non-nil *string")
	assert.Equal(t, "", *withEmpty.DefaultValue)

	// "hello" defaultValue → ArgDef.DefaultValue must be non-nil, pointing to "hello".
	withValue := argsByName["withValue"]
	require.NotNil(t, withValue)
	require.NotNil(t, withValue.DefaultValue)
	assert.Equal(t, "hello", *withValue.DefaultValue)
}

func TestNormalize_EmptyTypes(t *testing.T) {
	fixture := `{
  "data": {
    "__schema": {
      "queryType": null,
      "mutationType": null,
      "subscriptionType": null,
      "types": [],
      "directives": []
    }
  }
}`
	schema, err := Normalize(json.RawMessage(fixture))
	require.NoError(t, err)
	require.NotNil(t, schema, "must not return nil for empty types")
	assert.Empty(t, schema.Types)
	assert.Nil(t, schema.QueryType)
}
