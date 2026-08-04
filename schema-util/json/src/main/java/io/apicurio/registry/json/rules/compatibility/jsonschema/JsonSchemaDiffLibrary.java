package io.apicurio.registry.json.rules.compatibility.jsonschema;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import io.apicurio.registry.content.TypedContent;
import io.apicurio.registry.json.rules.compatibility.jsonschema.diff.DiffContext;
import io.apicurio.registry.json.rules.compatibility.jsonschema.diff.Difference;
import io.apicurio.registry.json.rules.compatibility.jsonschema.diff.SchemaDiffVisitor;
import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.everit.json.schema.loader.SpecificationVersion;
import org.everit.json.schema.loader.internal.ReferenceResolver;
import org.json.JSONObject;

import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static io.apicurio.registry.json.rules.compatibility.jsonschema.JsonUtil.MAPPER;
import static io.apicurio.registry.json.rules.compatibility.jsonschema.wrapper.WrapUtil.wrap;

public class JsonSchemaDiffLibrary {

    private static final String SCHEMA_KEYWORD = "$schema";

    /**
     * Find and analyze differences between two JSON schemas.
     *
     * @param original Original/Previous/First/Left JSON schema representation
     * @param updated Updated/Next/Second/Right JSON schema representation
     * @param resolvedReferences
     * @return an object to access the found differences: Original -&gt; Updated
     * @throws IllegalArgumentException if the input is not a valid representation of a JsonSchema
     */
    public static DiffContext findDifferences(String original, String updated,
                                              Map<String, TypedContent> resolvedReferences) {
        try {
            JsonNode originalNode = MAPPER.readTree(original);
            JsonNode updatedNode = MAPPER.readTree(updated);

            JSONObject originalJson = MAPPER.readValue(original, JSONObject.class);
            JSONObject updatedJson = MAPPER.readValue(updated, JSONObject.class);

            SchemaLoader.SchemaLoaderBuilder originalSchemaBuilder = SchemaLoader.builder()
                    .schemaClient(JsonUtil.DENY_REMOTE_SCHEMA_CLIENT);

            loadReferences(originalNode, resolvedReferences, originalSchemaBuilder);

            Schema originalSchema = originalSchemaBuilder.schemaJson(originalJson).build().load().build();

            SchemaLoader.SchemaLoaderBuilder updatedSchemaBuilder = SchemaLoader.builder()
                    .schemaClient(JsonUtil.DENY_REMOTE_SCHEMA_CLIENT);

            loadReferences(updatedNode, resolvedReferences, updatedSchemaBuilder);

            Schema updatedSchema = updatedSchemaBuilder.schemaJson(updatedJson).build().load().build();

            return findDifferences(originalSchema, updatedSchema);

        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void loadReferences(JsonNode jsonNode, Map<String, TypedContent> resolvedReferences,
            SchemaLoader.SchemaLoaderBuilder schemaLoaderBuilder) {
        SpecificationVersion spec = SpecificationVersion.DRAFT_7;
        if (jsonNode.has(SCHEMA_KEYWORD)) {
            String schema = jsonNode.get(SCHEMA_KEYWORD).asText();
            if (schema != null) {
                spec = SpecificationVersion.lookupByMetaSchemaUrl(schema)
                        .orElse(SpecificationVersion.DRAFT_7);
            }
        }

        URI idUri = null;
        if (jsonNode.has(spec.idKeyword())) {
            String id = jsonNode.get(spec.idKeyword()).asText();
            if (id != null) {
                idUri = ReferenceResolver.resolve((URI) null, id);
            }
        }

        Set<URI> registeredURIs = new HashSet<>();
        for (Map.Entry<String, TypedContent> stringStringEntry : resolvedReferences.entrySet()) {
            URI child = ReferenceResolver.resolve(idUri, stringStringEntry.getKey());
            schemaLoaderBuilder.registerSchemaByURI(child,
                    new JSONObject(stringStringEntry.getValue().getContent().content()));
            registeredURIs.add(child);
        }

        /*
         * Registering only the entries of the resolved reference map leaves any `$ref` that has no
         * recorded content to the library's default SchemaClient, which downloads the schema for
         * `http://` or opens a file for `file://`. So we walk the document and register every
         * reference it actually contains, using a placeholder schema that accepts any JSON when we
         * have no content for it. This mirrors JsonUtil#readSchemaEverit, keeping the compatibility
         * path in step with the validity path. An unresolved reference exposes no structure to
         * compare, so the placeholder does not weaken the diff.
         */
        for (URI extractedReference : JsonUtil.extractReferences(jsonNode)) {
            if (!registeredURIs.add(extractedReference)) {
                // Already registered above with content from the resolved reference map.
                continue;
            }
            TypedContent referenceContent = resolvedReferences.get(extractedReference.toString());
            schemaLoaderBuilder.registerSchemaByURI(extractedReference,
                    referenceContent != null
                            ? new JSONObject(referenceContent.getContent().content())
                            : new JSONObject());
        }
    }

    public static DiffContext findDifferences(Schema originalSchema, Schema updatedSchema) {
        DiffContext rootContext = DiffContext.createRootContext();
        new SchemaDiffVisitor(rootContext, originalSchema).visit(wrap(updatedSchema));
        return rootContext;
    }

    public static boolean isCompatible(String original, String updated,
            Map<String, TypedContent> resolvedReferences) {
        return findDifferences(original, updated, resolvedReferences).foundAllDifferencesAreCompatible();
    }

    public static Set<Difference> getIncompatibleDifferences(String original, String updated,
                                                             Map<String, TypedContent> resolvedReferences) {
        return findDifferences(original, updated, resolvedReferences).getIncompatibleDifferences();
    }
}