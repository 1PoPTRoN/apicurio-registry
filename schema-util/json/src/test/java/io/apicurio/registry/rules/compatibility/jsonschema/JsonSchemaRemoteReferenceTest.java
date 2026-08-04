package io.apicurio.registry.rules.compatibility.jsonschema;

import io.apicurio.registry.content.ContentHandle;
import io.apicurio.registry.content.TypedContent;
import io.apicurio.registry.json.rules.compatibility.jsonschema.JsonSchemaDiffLibrary;
import io.apicurio.registry.types.ContentTypes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the compatibility path never dereferences a `$ref` over the network. An unresolved
 * remote reference must be handled locally, otherwise a caller able to create an artifact version
 * while a COMPATIBILITY rule is active can make the server issue arbitrary outbound requests (SSRF).
 */
@Timeout(30)
public class JsonSchemaRemoteReferenceTest {

    private ServerSocket listener;
    private final AtomicBoolean connectionReceived = new AtomicBoolean(false);
    private Thread listenerThread;

    private static final byte[] SCHEMA_RESPONSE = ("HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: 2\r\n"
            + "Connection: close\r\n\r\n{}").getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void startListener() throws IOException {
        // Bound to the loopback interface on an ephemeral port: no external network is involved,
        // the socket exists purely to record whether the schema loader tried to reach out.
        listener = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        listener.setSoTimeout(500);
        listenerThread = new Thread(this::serveUntilClosed);
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    /**
     * Serves every connection until the listener is closed. A single-shot accept would deadlock the
     * unfixed code: findDifferences loads two schemas, so it issues two requests, and the second one
     * would block forever on a connection that is never answered (URL.openStream has no read
     * timeout). The failure has to be an assertion, not a hang.
     */
    private void serveUntilClosed() {
        while (!listener.isClosed()) {
            try (var socket = listener.accept()) {
                connectionReceived.set(true);
                // Answer with a valid schema so that the vulnerable code completes its load and the
                // assertion below fails on the SSRF rather than on an unrelated parse error.
                socket.getOutputStream().write(SCHEMA_RESPONSE);
                socket.getOutputStream().flush();
            } catch (SocketTimeoutException e) {
                // No connection within the poll interval; keep waiting until the socket is closed.
            } catch (IOException e) {
                return; // Listener closed during teardown.
            }
        }
    }

    @AfterEach
    void stopListener() throws Exception {
        listener.close();
        listenerThread.join(5000);
    }

    private String schemaWithRemoteRef() {
        return "{\n"
                + "  \"$id\": \"https://example.com/ssrf.schema.json\",\n"
                + "  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n"
                + "  \"type\": \"object\",\n"
                + "  \"properties\": {\n"
                + "    \"attacker\": { \"$ref\": \"http://127.0.0.1:" + listener.getLocalPort()
                + "/latest/meta-data/\" }\n"
                + "  }\n"
                + "}";
    }

    /**
     * FAILS before the fix: loadReferences registers only the entries of the resolved reference map,
     * so the unregistered `$ref` falls through to everit's default SchemaClient, which calls
     * URL.openStream() and connects to the listener.
     */
    @Test
    void testUnresolvedRemoteReferenceIsNotFetched() {
        String schema = schemaWithRemoteRef();

        JsonSchemaDiffLibrary.findDifferences(schema, schema, Collections.emptyMap());

        assertFalse(connectionReceived.get(),
                "Compatibility checking must not dereference a remote $ref over the network");
    }

    /**
     * The reference is unresolved on both sides, so it contributes no comparable structure and the
     * check must still succeed rather than fail closed on an unrelated error.
     */
    @Test
    void testUnresolvedRemoteReferenceRemainsCompatible() {
        String schema = schemaWithRemoteRef();

        assertTrue(JsonSchemaDiffLibrary.isCompatible(schema, schema, Collections.emptyMap()));
        assertFalse(connectionReceived.get());
    }

    /**
     * Regression guard: supplying the referenced content must still register that content, and the
     * placeholder must never shadow it.
     */
    @Test
    void testResolvedReferenceIsStillUsed() {
        String ref = "http://127.0.0.1:" + listener.getLocalPort() + "/latest/meta-data/";
        Map<String, TypedContent> resolved = Map.of(ref, TypedContent.create(
                ContentHandle.create("{\"type\": \"string\"}"), ContentTypes.APPLICATION_JSON));
        String schema = schemaWithRemoteRef();

        assertTrue(JsonSchemaDiffLibrary.isCompatible(schema, schema, resolved));
        assertFalse(connectionReceived.get());
    }

    /**
     * Regression guard: same-document references resolve through a different branch of the loader
     * (ReferenceLookup#isSameDocumentRef) and must keep detecting real incompatibilities.
     */
    @Test
    void testInternalReferenceStillDetectsIncompatibility() {
        String before = "{\n"
                + "  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n"
                + "  \"type\": \"object\",\n"
                + "  \"properties\": { \"address\": { \"$ref\": \"#/definitions/Address\" } },\n"
                + "  \"definitions\": { \"Address\": { \"type\": \"object\" } }\n"
                + "}";
        String after = "{\n"
                + "  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n"
                + "  \"type\": \"object\",\n"
                + "  \"properties\": { \"address\": { \"$ref\": \"#/definitions/Address\" } },\n"
                + "  \"definitions\": { \"Address\": { \"type\": \"string\" } }\n"
                + "}";

        assertTrue(JsonSchemaDiffLibrary.isCompatible(before, before, Collections.emptyMap()));
        assertFalse(JsonSchemaDiffLibrary.isCompatible(before, after, Collections.emptyMap()));
    }
}
