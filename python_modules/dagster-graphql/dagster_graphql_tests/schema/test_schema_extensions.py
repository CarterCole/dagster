import graphene
from dagster_graphql.schema import create_schema

def test_create_schema_with_extensions():
    class CustomQuery(graphene.ObjectType):
        custom_field = graphene.String()
        def resolve_custom_field(self, _info):
            return "custom"

    schema = create_schema(custom_query=CustomQuery)
    query_type = schema.get_query_type()
    assert "customField" in query_type.fields
    
    # Verify core fields still exist
    assert "repositoriesOrError" in query_type.fields

def test_create_schema_with_mutation_extensions():
    class CustomMutation(graphene.ObjectType):
        custom_mutation = graphene.Field(graphene.String)
        def resolve_custom_mutation(self, _info):
            return "done"

    schema = create_schema(custom_mutation=CustomMutation)
    mutation_type = schema.get_mutation_type()
    assert "customMutation" in mutation_type.fields
